require 'socket'
BasicSocket.do_not_reverse_lookup = true
client = UDPSocket.new
client.bind('10.0.0.3', 33333)
while true
data, addr = client.recvfrom(1024)
puts "From addr: '%s', msg: '%s'" % [addr.join(','), data]
end
client.close
