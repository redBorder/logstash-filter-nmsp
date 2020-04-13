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



class LogStash::Filters::Meraki < LogStash::Filters::Base
  include LocationConstant

  config_name "meraki"

  config :memcached_server, :validate => :string, :default => "", :required => false

  #Custom constants
  DATASOURCE =  "rb_location"
  NMSP_STORE_MEASURE = "nmsp-measure"
  NMSP_STORE_INFO = "nmsp-info"  

  public
  def register
    @dim_to_druid = [ MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID, DEPLOYMENT, 
                     DEPLOYMENT_UUID, SENSOR_NAME, SENSOR_UUID, NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID]

    @dim_to_cache = [WIRELESS_STATION, WIRELESS_CHANNEL, WIRELESS_ID, NMSP_DOT11PROTOCOL] 
    
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store = @memcached.get(LOCATION_STORE) || {}
    @storeMeasure = @memcached.get(NMSP_STORE_MEASURE) || {}
    @storeInfo = @memcached.get(NMSP_STORE_INFO) || {}
    @store_manager = StoreManager.new(@memcached)
    rssiLimit = (-85)
  end

  public
  def filter(event)
    toDruid = {}
    toCache = {}

    apMacs = []
    clientRssis = []

    clientMac = event.get(CLIENT_MAC)
    type = event.get((TYPE)
    enrichment = event.get("enrichment")

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    if type && type == NMSP_TYPE_MEASURE then
      # List<String> apMacs = (List<String>) message.get(NMSP_AP_MAC);
      dato_apMacs =  event.get(NMSP_AP_MAC)
      dato_apMacs.each{ |v| apMacs << v }
      # List<Integer> clientRssis = (List<Integer>) message.get(NMSP_RSSI);
      dato_rssi = event.get(NMSP_RSSI)
      dato_rssi.each{ |v| clientRssis << v.to_i }
      # message.remove(type);
      if ( clientRssis && !clientRssis.empty? ) && ( apMacs && !apMacs.empty? )
        rssi = clientRssis.max
        apMac = apMacs[clientRssis.index(rssi)] 
        infoCache = @storeInfo[clientMac + namespace_id]
        dot11_status = "PROBING"
         
        if infoCache.nil?
          toCache[CLIENT_RSSI_NUM] = rssi
          toCache[WIRELESS_STATION] = apMac
          toCache[NMSP_DOT11STATUS] =  "ASSOCIATED"
          dot11_status = "PROBING"
        else
          # Integer last_seen = (Integer) infoCache.get("last_seen");
          last_seen = infoCache["last_seen"].to_i
          
          if (last_seen + 3600) > Time.now.utc.to_i
            apAssociated = infoCache[WIRELESS_STATION]
            if apMacs.find(apAssociated)
              rssi = clientRssis[apMacs.index(ApAssociated)]
              toCache[CLIENT_RSSI_NUM] = rssi
              toCache.merge!(infoCache)
              dot11_status= "ASSOCIATED"  
            end
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
    end #if else
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Nmsp




__END__

    if clientMac then
      toDruid[CLIENT_MAC] =  clientMac
      @dim_to_druid.each { |dimension| toDruid[dimension] = event.get(dimension) if event.get(dimension) }
      
      toCache.merge!(enrichment) if enrichment
      
      rssi = event.get(CLIENT_RSSI_NUM).to_i

      if event.include?(SRC)
        toCache[DOT11STATUS] = "ASSOCIATED"
      else
        toCache[DOT11STATUS] = "PROBING"
      end

     if rssi
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
         # No seria "excellent"??  
         rssiName = "excelent"
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
     end
     
     @store[clientMac] = toCache
     @memcached.set(LOCATION_STORE, @store)
     toDruid.merge!(toCache)

     store_enrichment = @store_manager.enrich(toDruid)
     store_enrichment.merge!(toDruid)

     namespace = store_enrichment[NAMESPACE_UUID]
     datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

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

    else
      @logger.warn("This event #{event} doesn't have client mac.")
    end #if else
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Meraki
