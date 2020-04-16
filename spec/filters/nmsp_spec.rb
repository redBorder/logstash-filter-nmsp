# encoding: utf-8
require 'spec_helper'
require "logstash/filters/nmsp"
require 'dalli'


describe LogStash::Filters::Nmsp do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        nmsp {
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
