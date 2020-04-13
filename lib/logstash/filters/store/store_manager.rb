# encoding: utf-8
require "dalli"
require_relative "../util/location_constant"

class StoreManager
  include LocationConstant

  attr_accessor :memcached

  def initialize(memcached)
    @memcached = memcached
  end
 
  def get_store_keys(store_name)
    return ["wireless_station"] if store_name == WLC_PSQL_STORE
    return ["sensor_uuid"] if store_name == SENSOR_PSQL_STORE
    return ["client_mac","namespace_uuid"]
  end
  
  def must_overwrite?(store_name)
   [WLC_PSQL_STORE, SENSOR_PSQL_STORE, 
    NMSP_STORE_MEASURE, NMSP_STORE_INFO].include?store_name ? false : true
  end

  def get_store(store_name)
    @memcached.get(store_name) || {}
  end

  def enrich(message)
    enrichment = {}
    enrichment.merge!(message)

    stores_list = [WLC_PSQL_STORE, SENSOR_PSQL_STORE, 
                   NMSP_STORE_MEASURE,NMSP_STORE_INFO,
                   RADIUS_STORE,LOCATION_STORE,DWELL_STORE]

    stores_list.each do |store_name|
      if store_name == SENSOR_PSQL_STORE || store_name == WLC_PSQL_STORE
        store_data = get_store(store_name)
        keys = get_store_keys(store_name)
        namespace = message[NAMESPACE_UUID]
        mergekey = ""
        keys.each { |kv| mergekey << enrichment[kv] if enrichment[kv] }
        contents = store_data[mergekey] ? store_data[mergekey] : (store_data[enrichment[keys.first]] if enrichment[keys.first])
        if contents
           psql_namespace = contents[NAMESPACE_UUID]
           if namespace && psql_namespace
               if namespace == psql_namespace
                 must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment)
               end
           else
               must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment)
           end
        end      
      else
        store_data = get_store(store_name)
        keys = get_store_keys(store_name)
        mergekey = ""
        keys.each { |kv| mergekey << enrichment[kv] if enrichment[kv] }
        contents = store_data[mergekey]
        if contents
          must_overwrite?(store_name) ? enrichment.merge!(contents) : enrichment = contents.merge(enrichment)
        end
      end
    end  #end bucle
    return enrichment
  end    # end Enrich
end      # end StoreManager
