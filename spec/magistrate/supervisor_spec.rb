require "spec_helper"
require "magistrate/supervisor"

describe "Magistrate::Supervisor" do
  before(:each) do
    @supervisor = Magistrate::Supervisor.new("spec/resources/example.yml")
  end
  
  it "should initialize correctly" do
    lambda { Magistrate::Supervisor.new("spec/resources/example.yml") }.should_not raise_error
  end
  
  it "should show basic status for its workers" do
    s = @supervisor.status
    
    s[:name].should == 'test_name'
    s[:pid_path].should == File.join('tmp','pids')
    
  end
  
  it 'should run successfully' do
    body = {}
    body = JSON.generate(body)
    stub_request(:get, "http://localhost:3000/magistrate/api/status/test_name").
      to_return(:status => 200, :body => body, :headers => {})
      
    stub_request(:post, "http://localhost:3000/magistrate/api/status/test_name").
      to_return(:status => 200, :body => 'OK', :headers => {})
      
    
    
    @supervisor.run
    
    a_request(:get, "http://localhost:3000/magistrate/api/status/test_name").should have_been_made
    a_request(:post, "http://localhost:3000/magistrate/api/status/test_name").should have_been_made
  end
end