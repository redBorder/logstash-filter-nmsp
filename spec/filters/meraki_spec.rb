# encoding: utf-8
require 'spec_helper'
require "logstash/filters/meraki"
require 'dalli'

describe LogStash::Filters::Meraki do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        meraki {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('Hello World')
    end
  end
end
