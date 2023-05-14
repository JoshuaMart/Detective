# frozen_string_literal: true

# !/usr/bin/env ruby

require 'optparse'
require 'yaml'
require_relative 'recon/recon'

options = {
  base_path: './detective'
}

optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: detective.rb [options]'

  opts.on('-h', '--help', 'Display this screen') do
    puts opts
    exit
  end

  opts.on('-d', '--domain domain', 'Domain to scan') do |value|
    options[:domain] = value
  end

  opts.on('-m', '--minimize', 'Minimize HTTPX results') do
    options[:minimize] = true
  end

  opts.on('-s', '--silent', 'Does not display logs messages') do
    options[:silent] = true
  end

  opts.on('--vhosts', 'vHosts bruteforce') do
    options[:vhosts] = true
  end
end

begin
  optparse.parse!
rescue OptionParser::InvalidOption
  puts 'See detective.rb -h'
  exit
end

global = YAML.load_file(File.join(options[:base_path], '/configs/global.yaml'))
options.merge!(global)
options.transform_keys!(&:to_sym)

scan = Scan.new(options)
scan.recon
