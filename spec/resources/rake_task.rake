namespace :worker do
  task :test do
    
    trap('USR1') {
      puts 'Doing good'
    }
    
    while true do
      puts '1'
      sleep(3)
    end
  end
end






