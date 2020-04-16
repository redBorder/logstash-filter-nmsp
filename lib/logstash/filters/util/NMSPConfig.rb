require "yaml"

module NMSPConfig

  NMSP_CONFIG_FILE="/opt/rb/etc/nmspd/config.yml" unless defined? NMSP_CONFIG_FILE
  RSSI_DEFAULT = -85
  
  def self.read_value
    nmsp_config = []
    if File.exist?(NMSP_CONFIG_FILE)
      nmsp_config = YAML.load_file(NMSP_CONFIG_FILE)
      return nmsp_confi["rssi_limit_db"]
    else
      return RSSI_DEFAULT
    end
  end
end
  
