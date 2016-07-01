require "rubygems"
require "bundler/setup"
require 'bundler/gem_tasks'
require 'rake/testtask'

namespace :test do
  Rake::TestTask.new(:units) do |t|
    t.pattern = "spec/*_spec.rb"
    t.warning = false
  end

  Rake::TestTask.new(:integration) do |t|
    t.pattern = "spec/integration/*_spec.rb"
  end
end

desc 'Run tests'
task :test => %w[test:units test:integration]

task :default => :test
