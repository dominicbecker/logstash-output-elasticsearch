require "logstash/outputs/elasticsearch/template_manager"
require "logstash/outputs/elasticsearch/buffer"

module LogStash; module Outputs; class ElasticSearch;
  module Common
    attr_reader :client, :hosts

    RETRYABLE_CODES = [429, 503]
    SUCCESS_CODES = [200, 201]

    def register
      @stopping = Concurrent::AtomicBoolean.new(false)
      setup_hosts # properly sets @hosts
      build_client
      install_template
      setup_buffer_and_handler
      check_action_validity
      setup_size_checker

      @logger.info("New Elasticsearch output", :class => self.class.name, :hosts => @hosts)
    end

    def receive(event)
      @buffer << event_action_tuple(event)
    end

    # Receive an array of events and immediately attempt to index them (no buffering)
    def multi_receive(events)
      events.each_slice(@flush_size) do |slice|
        retrying_submit(slice.map {|e| event_action_tuple(e) })
      end
    end

    # Convert the event into a 3-tuple of action, params, and event
    def event_action_tuple(event)
      params = event_action_params(event)
      action = event.sprintf(@action)
      [action, params, event]
    end

    def flush
      @buffer.flush
    end

    def setup_hosts
      @hosts = Array(@hosts)
      if @hosts.empty?
        @logger.info("No 'host' set in elasticsearch output. Defaulting to localhost")
        @hosts.replace(["localhost"])
      end
    end

    def install_template
      TemplateManager.install_template(self)
    end

    def setup_buffer_and_handler
      @buffer = ::LogStash::Outputs::ElasticSearch::Buffer.new(@logger, @flush_size, @idle_flush_time) do |actions|
        retrying_submit(actions)
      end
    end

    def setup_size_checker
      if @index =~ /\%\{num\}/
        if !@size_check_interval.is_a?(Integer) || @size_check_interval <= 0
          raise LogStash::ConfigurationError, "size_check_interval must be a positive integer"
        end
        if !@size_rotation_start_at.is_a?(Integer) || @size_rotation_start_at <= 0
          raise LogStash::ConfigurationError, "size_rotation_start_at must be a positive integer"
        end

        # initial size check to choose index seqno
        loop do
          if safe_size_check
            break
          else
            # keep trying
            # if it doesn't succeed, indexing wouldn't either
            sleep @size_check_interval
          end
        end

        @size_check_thread = spawn_size_checker
      end
    end

    # do_size_check with exception handling
    # returns true on success, false on failure
    def safe_size_check
      begin
        do_size_check
        return true
      rescue Manticore::SocketException,
        Manticore::SocketTimeout,
        Elasticsearch::Transport::Transport::Errors::ServiceUnavailable => e
        @logger.error(
          "Attempted to perform index size check in Elasticsearch configured at '#{@client.client_options[:hosts]}',"+
            " but Elasticsearch appears to be unreachable or down!",
          :error_message => e.message,
          :class => e.class.name,
          :client_config => @client.client_options,
        )

        return false
      end
    end

    def do_size_check
      @logger.info("Querying stats for size checker")
      stats = @client.store_stats

      # %{num} will contain the index number
      index_pattern = Regexp.new(@index.gsub '%{num}', '(\d+)')
      # escape other "%" to avoid being treated as format
      index_fmt = @index.gsub('%', '%%').gsub('%%{num}', '%d')

      # determine current index number
      latest_num = @size_rotation_start_at
      latest_size = nil
      stats['indices'].each do |index,store|
        if index =~ index_pattern
          cur_num = $1.to_i
          if cur_num >= latest_num
            latest_num = cur_num
            latest_size = store['primaries']['store']['size_in_bytes']
          end
        end
      end

      # determine whether we should change index number to next
      # if so, update @cur_index
      num = nil
      if latest_size != nil && latest_size >= @index_max_bytes
        num = latest_num + 1
        @logger.info("Size-based index rotation, max size reached for %s. Moving to number %d." % [ @cur_index, num ])
      else
        num = latest_num
        @logger.info("Size-based index rotation, latest number exists (or first index to be created) for %s. Using number %d." % [ @index, num ])
      end

      if num != nil
        @logger.info("Updating size-based index rotation index pattern")
        @cur_index = index_fmt % [ num ]
      end
    end

    def spawn_size_checker
      Thread.new do
        loop do
          sleep @size_check_interval
          break if @stopping.true?
          # keep running even if the check fails
          # if it doesn't succeed, indexing shouldn't either
          safe_size_check
        end
      end
    end

    def check_action_validity
      raise LogStash::ConfigurationError, "No action specified!" unless @action

      # If we're using string interpolation, we're good!
      return if @action =~ /%{.+}/
      return if valid_actions.include?(@action)

      raise LogStash::ConfigurationError, "Action '#{@action}' is invalid! Pick one of #{valid_actions} or use a sprintf style statement"
    end

    # To be overidden by the -java version
    VALID_HTTP_ACTIONS=["index", "delete", "create", "update"]
    def valid_actions
      VALID_HTTP_ACTIONS
    end

    def retrying_submit(actions)
      # Initially we submit the full list of actions
      submit_actions = actions

      while submit_actions && submit_actions.length > 0
        return if !submit_actions || submit_actions.empty? # If everything's a success we move along
        # We retry with whatever is didn't succeed
        begin
          submit_actions = submit(submit_actions)
        rescue => e
          @logger.warn("Encountered an unexpected error submitting a bulk request! Will retry.",
                       :message => e.message,
                       :class => e.class.name,
                       :backtrace => e.backtrace)
        end

        sleep @retry_max_interval if submit_actions && submit_actions.length > 0
      end
    end

    def submit(actions)
      es_actions = actions.map { |a, doc, event| [a, doc, event.to_hash]}

      bulk_response = safe_bulk(es_actions,actions)

      # If there are no errors, we're done here!
      return unless bulk_response["errors"]

      actions_to_retry = []
      bulk_response["items"].each_with_index do |response,idx|
        action_type, action_props = response.first
        status = action_props["status"]
        error  = action_props["error"]
        action = actions[idx]

        if SUCCESS_CODES.include?(status)
          next
        elsif RETRYABLE_CODES.include?(status)
          @logger.info "retrying failed action with response code: #{status} (#{error})"
          actions_to_retry << action
        else
          @logger.warn "Failed action. ", status: status, action: action, response: response
        end
      end

      actions_to_retry
    end

    # get the action parameters for the given event
    def event_action_params(event)
      type = get_event_type(event)

      # apply size-rotation index numbering first
      if @cur_index != nil
        index = @cur_index
      else
        index = @index
      end

      index = event.sprintf(index)

      params = {
        :_id => @document_id ? event.sprintf(@document_id) : nil,
        :_index => index,
        :_type => type,
        :_routing => @routing ? event.sprintf(@routing) : nil
      }

      params[:parent] = event.sprintf(@parent) if @parent
      if @action == 'update'
        params[:_upsert] = LogStash::Json.load(event.sprintf(@upsert)) if @upsert != ""
        params[:_script] = event.sprintf(@script) if @script != ""
        params[:_retry_on_conflict] = @retry_on_conflict
      end
      params
    end

    # Determine the correct value for the 'type' field for the given event
    def get_event_type(event)
      # Set the 'type' value for the index.
      type = if @document_type
               event.sprintf(@document_type)
             else
               event["type"] || "logs"
             end

      if !(type.is_a?(String) || type.is_a?(Numeric))
        @logger.warn("Bad event type! Non-string/integer type value set!", :type_class => type.class, :type_value => type.to_s, :event => event)
      end

      type.to_s
    end

    # Rescue retryable errors during bulk submission
    def safe_bulk(es_actions,actions)
      @client.bulk(es_actions)
    rescue Manticore::SocketException, Manticore::SocketTimeout => e
      # If we can't even connect to the server let's just print out the URL (:hosts is actually a URL)
      # and let the user sort it out from there
      @logger.error(
        "Attempted to send a bulk request to Elasticsearch configured at '#{@client.client_options[:hosts]}',"+
          " but Elasticsearch appears to be unreachable or down!",
        :error_message => e.message,
        :class => e.class.name,
        :client_config => @client.client_options,
      )
      @logger.debug("Failed actions for last bad bulk request!", :actions => actions)

      # We retry until there are no errors! Errors should all go to the retry queue
      sleep @retry_max_interval
      retry unless @stopping.true?
    rescue => e
      # For all other errors print out full connection issues
      @logger.error(
        "Attempted to send a bulk request to Elasticsearch configured at '#{@client.client_options[:hosts]}'," +
          " but an error occurred and it failed! Are you sure you can reach elasticsearch from this machine using " +
          "the configuration provided?",
        :error_message => e.message,
        :error_class => e.class.name,
        :backtrace => e.backtrace,
        :client_config => @client.client_options,
      )

      @logger.debug("Failed actions for last bad bulk request!", :actions => actions)

      raise e
    end
  end
end; end; end
