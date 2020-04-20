# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "util/NMSPConfig"
require_relative "store/store_manager"



class LogStash::Filters::Nmsp < LogStash::Filters::Base
  include LocationConstant

  config_name "nmsp"

  config :memcached_server, :validate => :string, :default => "", :required => false

  #Custom constants
  DATASOURCE =  "rb_location"
  # NMSP_STORE_MEASURE = "nmsp-measure"
  # NMSP_STORE_INFO = "nmsp-info"

  #NMSP CONSTANT
  # RSSILIMIT = -85

  public
  def register
    @dim_to_druid = [ MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID, DEPLOYMENT, 
                     DEPLOYMENT_UUID, SENSOR_NAME, SENSOR_UUID, NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID]

    @dim_to_cache_info = [WIRELESS_STATION, WIRELESS_CHANNEL, WIRELESS_ID, NMSP_DOT11PROTOCOL] 
    
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
    
    @store = @memcached.get(LOCATION_STORE) || {}
    @store_manager = StoreManager.new(@memcached)
    @store_measure = @store_manager.get_store(NMSP_STORE_MEASURE) || {}
    @store_info = @store_manager.get_store(NMSP_STORE_INFO) || {}
    @rssi_limit = NMSPConfig::read_value 
  end

  public
  def filter(event)
    toDruid = {}
    toCache = {}

    apMacs = []
    clientRssis = []

    type = event.get(TYPE)
    clientMac = event.get(CLIENT_MAC)

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    if type && type == NMSP_TYPE_MEASURE then
      # List<String> apMacs = (List<String>) message.get(NMSP_AP_MAC);
      apMacs =  event.get(NMSP_AP_MAC)
      # List<Integer> clientRssis = (List<Integer>) message.get(NMSP_RSSI);
      clientRssis = event.get(NMSP_RSSI)
      # message.remove(type);
      event.remove(type)
      if ( clientRssis && !clientRssis.empty? ) && ( apMacs && !apMacs.empty? )
        rssi = clientRssis.max
        apMac = apMacs[clientRssis.index(rssi)] 
        infoCache = @store_info[clientMac + namespace_id]
        dot11_status = "PROBING"
         
        if infoCache.nil?
          toCache[CLIENT_RSSI_NUM] = rssi
          toCache[WIRELESS_STATION] = apMac
          toCache[NMSP_DOT11STATUS] = "ASSOCIATED"
          dot11_status = "PROBING"
        else
          # Integer last_seen = (Integer) infoCache.get("last_seen");
          last_seen = infoCache["last_seen"].to_i
          
          if (last_seen + 3600) > Time.now.utc.to_i
            apAssociated = infoCache[WIRELESS_STATION]
            if apMacs.include?(apAssociated)
              rssi = clientRssis[apMacs.index(apAssociated)]
              toCache[CLIENT_RSSI_NUM] = rssi
              toCache.merge!(infoCache)
              dot11_status= "ASSOCIATED"  
            else
              toDruid = nil
            end
          else #last_seen
            @store_info.delete(clientMac + namespace_id)
            @store_manager.put_store(NMSP_STORE_INFO, @store_info)
            toCache[CLIENT_RSSI_NUM] = rssi
            toCache[WIRELESS_STATION] = apMac
            toCache[NMSP_DOT11STATUS] =  "ASSOCIATED"
            dot11_status = "PROBING"
          end         
        end #InfoCache.nil?
        if rssi == 0
          rssiName = "unknown"
        elsif rssi <= (-85)
          rssiName = "bad"
        elsif rssi <= (-80)
          rssiName = "low"
        elsif rssi <= (-70)
          rssiName = "medium"
        elsif rssi <= (-60)
          rssiName = "good"
        else
          rssiName = "excellent"
        end
        toCache[CLIENT_RSSI] = rssiName

        if rssi == 0
          toCache[CLIENT_PROFILE] = "hard"
        elsif rssi <= (-75)
          toCache[CLIENT_PROFILE] = "soft"
        elsif rssi <= (-65)
          toCache[CLIENT_PROFILE] = "medium"
        else
          toCache[CLIENT_PROFILE] = "hard"
        end

        if toDruid
          @dim_to_druid.each { |dimension| (toDruid[dimension] = event.get(dimension)) if event.get(dimension) }
          toDruid[TYPE] = "nmsp-measure"
          toDruid[CLIENT_MAC] = clientMac
          toDruid.merge!(toCache);
          toDruid[NMSP_DOT11STATUS] = dot11_status
          toDruid[CLIENT_RSSI_NUM] = rssi
          toDruid[CLIENT_RSSI] = rssiName

          timestamp = event.get(TIMESTAMP) ? event.get(TIMESTAMP) : Time.now.utc.to_i
         
          toDruid["timestamp"] = timestamp 
          
          if namespace_id != "" then
            toDruid[NAMESPACE_UUID] = namespace_id
          end 
          @store_measure[clientMac + namespace_id] = toCache
          @store_manager.put_store(NMSP_STORE_MEASURE, @store_measure)

          store_enrichment = @store_manager.enrich(toDruid)
          store_enrichment.merge!(toDruid)

          namespace_UUID = store_enrichment[NAMESPACE_UUID]
          datasource = (namespace_UUID) ? DATASOURCE + "_" + namespace_UUID : DATASOURCE
          counterStore = @memcached.get(COUNTER_STORE)
          counterStore = Hash.new if counterStore.nil?
          counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource] + 1)
          @memcached.set(COUNTER_STORE,counterStore)
 
          flowsNumber = @memcached.get(FLOWS_NUMBER)
          flowsNumber = Hash.new if flowsNumber.nil?
          store_enrichment["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]

          if rssi >= @rssi_limit || dot11_status == "ASSOCIATED"
            enrichmentEvent = LogStash::Event.new
            store_enrichment.each {|k,v| enrichmentEvent.set(k,v)}
            yield enrichmentEvent
          end #if new event
        end #toDruid
      end  #if rssi
# ---------------------------------------------------------------
    elsif type && type == NMSP_TYPE_INFO
      
      vlan = event.remove(NMSP_VLAN_ID)
      event.remove(type)
 
      toCache[LAN_VLAN] = vlan if vlan
      
      timestamp = event.get("timestamp") ? event.get(TIMESTAMP).to_i : Time.now.utc.to_i
      
      @dim_to_cache_info.each { |dimension| (toCache[dimension] = event.get(dimension)) if event.get(dimension) }
      
      toCache["last_seen"] = timestamp
      toCache[NMSP_DOT11STATUS] = "ASSOCIATED"
      toDruid.merge!(toCache)

      @dim_to_druid.each { |dimension| (toDruid[dimension] = event.get(dimension)) if event.get(dimension) }
      toDruid["timestamp"] = timestamp
      toDruid[TYPE] = "nmsp-info"
      toDruid[NAMESPACE_UUID] = namespace_id if namespace_id != ""
      toDruid[CLIENT_PROFILE] = "hard"
      toDruid[CLIENT_MAC] = clientMac
      @store_info[clientMac + namespace_id] = toCache
      @store_manager.put_store(NMSP_STORE_INFO, @store_info)    #almacenado en memcached

      store_enrichment = @store_manager.enrich(toDruid)
      store_enrichment.merge!(toDruid)

      namespace_UUID = store_enrichment[NAMESPACE_UUID]
      datasource = (namespace_UUID) ? DATASOURCE + "_" + namespace_UUID : DATASOURCE
      
      counterStore = @memcached.get(COUNTER_STORE)
      counterStore = Hash.new if counterStore.nil?
      counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource] + 1)
      @memcached.set(COUNTER_STORE,counterStore)
 
      flowsNumber = @memcached.get(FLOWS_NUMBER)
      flowsNumber = Hash.new if flowsNumber.nil?
      store_enrichment["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]

      enrichmentEvent = LogStash::Event.new
      store_enrichment.each {|k,v| enrichmentEvent.set(k,v)}
      yield enrichmentEvent
    end #if else
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Nmsp

