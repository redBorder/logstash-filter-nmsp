# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"

class LogStash::Filters::Nmsp < LogStash::Filters::Base
  include LocationConstant

  config_name "nmsp"

  config :memcached_server, :validate => :string, :default => "", :required => false
  config :rssi_limit, :validate => :number, :default => -80, :required => false

  #Custom constants
  DATASOURCE =  "rb_location"

  public
  def register
    @dim_to_druid = [ MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID, DEPLOYMENT, 
                     DEPLOYMENT_UUID, SENSOR_NAME, SENSOR_UUID, NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID]

    @dim_to_cache_info = [WIRELESS_STATION, WIRELESS_CHANNEL, WIRELESS_ID, NMSP_DOT11PROTOCOL] 
    
    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
    
    @store = @memcached.get(LOCATION_STORE) || {}
    @store_manager = StoreManager.new(@memcached)
    @store_measure = @store_manager.get_store(NMSP_STORE_MEASURE) || {}
    @store_info = @store_manager.get_store(NMSP_STORE_INFO) || {}
  end

  public

  def filter(event)
    to_druid = {}
    to_cache = {}

    ap_macs = []
    client_rssis = []

    type = event.get(TYPE)
    client_mac = event.get(CLIENT_MAC)

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    if type && type == NMSP_TYPE_MEASURE then
      # List<String> ap_macs = (List<String>) message.get(NMSP_AP_MAC);
      ap_macs =  event.get(NMSP_AP_MAC)
      # List<Integer> client_rssis = (List<Integer>) message.get(NMSP_RSSI);
      client_rssis = event.get(NMSP_RSSI)
      # message.remove(type);
      event.remove(type)
      if ( client_rssis && !client_rssis.empty? ) && ( ap_macs && !ap_macs.empty? )
        rssi = client_rssis.max
        ap_mac = ap_macs[client_rssis.index(rssi)] 
        info_cache = @store_info[client_mac + namespace_id]
        dot11_status = "PROBING"
         
        if info_cache.nil?
          to_cache[CLIENT_RSSI_NUM] = rssi
          to_cache[WIRELESS_STATION] = ap_mac
          to_cache[NMSP_DOT11STATUS] = "ASSOCIATED"
          dot11_status = "PROBING"
        else
          # Integer last_seen = (Integer) info_cache.get("last_seen");
          last_seen = info_cache["last_seen"].to_i
          
          if (last_seen + 3600) > Time.now.utc.to_i
            ap_associated = info_cache[WIRELESS_STATION]
            if ap_macs.include?(ap_associated)
              rssi = client_rssis[ap_macs.index(ap_associated)]
              to_cache[CLIENT_RSSI_NUM] = rssi
              to_cache.merge!(info_cache)
              dot11_status= "ASSOCIATED"  
            else
              to_druid = nil
            end
          else #last_seen
            @store_info.delete(client_mac + namespace_id)
            @memcached.set(NMSP_STORE_INFO, @store_info)
            to_cache[CLIENT_RSSI_NUM] = rssi
            to_cache[WIRELESS_STATION] = ap_mac
            to_cache[NMSP_DOT11STATUS] =  "ASSOCIATED"
            dot11_status = "PROBING"
          end         
        end #InfoCache.nil?
        if rssi == 0
          rssi_name = "unknown"
        elsif rssi <= (-85)
          rssi_name = "bad"
        elsif rssi <= (-80)
          rssi_name = "low"
        elsif rssi <= (-70)
          rssi_name = "medium"
        elsif rssi <= (-60)
          rssi_name = "good"
        else
          rssi_name = "excellent"
        end
        to_cache[CLIENT_RSSI] = rssi_name

        if rssi == 0
          to_cache[CLIENT_PROFILE] = "hard"
        elsif rssi <= (-75)
          to_cache[CLIENT_PROFILE] = "soft"
        elsif rssi <= (-65)
          to_cache[CLIENT_PROFILE] = "medium"
        else
          to_cache[CLIENT_PROFILE] = "hard"
        end

        if to_druid
          @dim_to_druid.each { |dimension| (to_druid[dimension] = event.get(dimension)) if event.get(dimension) }
          to_druid[TYPE] = "nmsp-measure"
          to_druid[CLIENT_MAC] = client_mac
          to_druid.merge!(to_cache);
          to_druid[NMSP_DOT11STATUS] = dot11_status
          to_druid[CLIENT_RSSI_NUM] = rssi
          to_druid[CLIENT_RSSI] = rssi_name

          timestamp = event.get(TIMESTAMP) ? event.get(TIMESTAMP) : Time.now.utc.to_i
         
          to_druid["timestamp"] = timestamp 
          
          if namespace_id != "" then
            to_druid[NAMESPACE_UUID] = namespace_id
          end 
          @store_measure[client_mac + namespace_id] = to_cache
          @memcached.set(NMSP_STORE_MEASURE, @store_measure)

          store_enrichment = @store_manager.enrich(to_druid)
          store_enrichment.merge!(to_druid)

          datasource = DATASOURCE
          namespace = store_enrichment[NAMESPACE_UUID]
          datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE if (namespace && !namespace.empty?)

          counter_store = @memcached.get(COUNTER_STORE)
          counter_store = Hash.new if counter_store.nil?
          counter_store[datasource] = counter_store[datasource].nil? ? 0 : (counter_store[datasource] + 1)
          @memcached.set(COUNTER_STORE,counter_store)
 
          flows_number = @memcached.get(FLOWS_NUMBER)
          flows_number = Hash.new if flows_number.nil?
          store_enrichment["flows_count"] = flows_number[datasource] if flows_number[datasource]

          if rssi >= @rssi_limit || dot11_status == "ASSOCIATED"
            enrichment_event = LogStash::Event.new
            store_enrichment.each {|k,v| enrichment_event.set(k,v)}
            yield enrichment_event
          end #if new event
        end #to_druid
      end  #if rssi
# ---------------------------------------------------------------
    elsif type && type == NMSP_TYPE_INFO
      
      vlan = event.remove(NMSP_VLAN_ID)
      event.remove(type)
 
      to_cache[LAN_VLAN] = vlan if vlan
      
      timestamp = event.get("timestamp") ? event.get(TIMESTAMP).to_i : Time.now.utc.to_i
      
      @dim_to_cache_info.each { |dimension| (to_cache[dimension] = event.get(dimension)) if event.get(dimension) }
      
      to_cache["last_seen"] = timestamp
      to_cache[NMSP_DOT11STATUS] = "ASSOCIATED"
      to_druid.merge!(to_cache)

      @dim_to_druid.each { |dimension| (to_druid[dimension] = event.get(dimension)) if event.get(dimension) }
      to_druid["timestamp"] = timestamp
      to_druid[TYPE] = "nmsp-info"
      to_druid[NAMESPACE_UUID] = namespace_id if namespace_id != ""
      to_druid[CLIENT_PROFILE] = "hard"
      to_druid[CLIENT_MAC] = client_mac
      @store_info[client_mac + namespace_id] = to_cache
      @memcached.set(NMSP_STORE_INFO, @store_info)    #almacenado en memcached

      store_enrichment = @store_manager.enrich(to_druid)
      store_enrichment.merge!(to_druid)

      namespace_UUID = store_enrichment[NAMESPACE_UUID]
      datasource = (namespace_UUID) ? DATASOURCE + "_" + namespace_UUID : DATASOURCE
      
      counter_store = @memcached.get(COUNTER_STORE)
      counter_store = Hash.new if counter_store.nil?
      counter_store[datasource] = counter_store[datasource].nil? ? 0 : (counter_store[datasource] + 1)
      @memcached.set(COUNTER_STORE,counter_store)
 
      flows_number = @memcached.get(FLOWS_NUMBER)
      flows_number = Hash.new if flows_number.nil?
      store_enrichment["flows_count"] = flows_number[datasource] if flows_number[datasource]

      enrichment_event = LogStash::Event.new
      store_enrichment.each {|k,v| enrichment_event.set(k,v)}
      yield enrichment_event
    end #if else

    event.cancel
  end   # def filter
end     # class Logstash::Filter::Nmsp

