require "spec_helper"
require "magistrate/worker"

describe "Magistrate::Worker" do
  describe "integration tests" do
    before(:each) do
      #      Dir.glob('spec/tmp/pids/*').each do |f|
      #        File.delete(f)
      #      end
      @worker = Magistrate::Worker.new(
      'rake_like_worker',
      :daemonize => true,
      :start_cmd => 'ruby spec/resources/rake_like_worker.rb',
      :pid_path => 'spec/tmp/pids',
      :working_dir => "spec/tmp",
      :debug => true
      )
      
      @worker2 = Magistrate::Worker.new(
      'rake_task',
      :daemonize => true,
      :start_cmd => 'rake -f spec/resources/rake_task.rake worker:test',
      :pid_path => 'spec/tmp/pids',
      :working_dir => "spec/tmp",
      :debug => true
      )
    end

    describe "extra processes command check" do
      it "should find extra processes associated with master process" do
        cmd = @worker.start_cmd
        Kernel.fork do
          `#{cmd}`
        end
        the_pid = @worker.find_pid_for_current_command
        the_pid.should_not be_blank
        @worker.is_rake_cmd?.should be_false
        sleep(1)
        Process.kill("KILL", the_pid)
        
      end
    end
    
    describe "extra rake processes check" do
      it "should find extra rake processes associated with master process" do
        cmd = @worker2.start_cmd
        Kernel.fork do
          `#{cmd}`
        end
        the_pid = @worker2.find_pid_for_current_command
        the_pid.should_not be_blank
        @worker2.is_rake_cmd?.should be_true
        sleep(1)
        Process.kill("KILL", the_pid)
        
      end
    end
  end

  describe 'Rake-Like Worker' do
    around(:each) do |example|
      FakeFS.activate!
      example.run
      FakeFS.deactivate!
    end
    
    before(:each) do
#      Dir.glob('spec/tmp/pids/*').each do |f|
#        File.delete(f)
#      end
      @worker = Magistrate::Worker.new(
        'rake_like_worker',
        :daemonize => true,
        :start_cmd => 'ruby spec/resources/rake_like_worker.rb',
        :pid_path => 'spec/tmp/pids'
      )
      
      stub(@worker).spawn do 
        raise "Unexpected spawn call made...you don't want your specs actually spawning stuff, right?"
      end
    end
    
   
    describe 'state' do
      it 'should be unmonitored by default' do
        @worker.state.should == :unmonitored
      end
      
      it 'should be unmonitored when unmonitored is the target state' do
        @worker.target_state =  :unmonitored
        @worker.state.should == :unmonitored
      end
      
      it 'should be stopped when target state other that unmonitored' do
        @worker.target_state = :foo
        @worker.state.should == :stopped
      end
    end

    describe 'bounces' do
      it 'should start with 0 bounces' do
        @worker.bounces.should == 0
      end

      it 'should show a bounce' do
        stub(@worker).alive? { false }
        mock(@worker).start { true }
        @worker.target_state = :running
        @worker.supervise!
        @worker.bounces.should == 1
      end

      it 'should show no bounce' do
        stub(@worker).alive? { true }
        @worker.target_state = :running
        @worker.supervise!
        @worker.bounces.should == 0
      end

      it 'should show a bounce, then reload it' do
        stub(@worker).alive? { false }
        mock(@worker).start { true }
        @worker.target_state = :running
        @worker.supervise!
        @worker.bounces.should == 1

        @worker2 = Magistrate::Worker.new(
          'rake_like_worker',
          :daemonize => true,
          :start_cmd => 'ruby spec/resources/rake_like_worker.rb',
          :pid_path => 'spec/tmp/pids'
        )

        # The second worker should load the config of the first
        @worker2.bounces.should == 1


        stub(@worker2).alive? { true }
        @worker2.target_state = :running
        @worker2.supervise!

        @worker2.bounces.should == 0

        @worker3 = Magistrate::Worker.new(
          'rake_like_worker',
          :daemonize => true,
          :start_cmd => 'ruby spec/resources/rake_like_worker.rb',
          :pid_path => 'spec/tmp/pids'
        )

        # Third worker should load the config of the second
        @worker3.bounces.should == 0
      end
    end
  end
  
  describe 'Self-Daemonizing Worker' do
    
  end
end
