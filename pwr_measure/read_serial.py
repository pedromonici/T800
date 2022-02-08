import serial
import time
import sys
import zmq

# set the arduino COM PORT
port = "/dev/ttyACM0"
baud_rate = 115200
path = "./output/" 

ser = serial.Serial(port, baud_rate)

# configuration settings for ZeroMQ (zmq)
context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:5555")

print("> Starting...")
while True:

    message = socket.recv()
    print("> Received request: %s" % message)

    if message == "STOP": # stop serial monitor
        break

    # Message composed by CSV values:
    # Bus voltage (V), Shunt voltage (mV), Load Voltage (V), Current (mA), Power (mW), Discrete Signal from ESP
    #
    
    serial_msg = ""
    if len(message) > 1:
        file_name = path + str(message).replace("'","").replace("\"","") + ".csv"
    else:
        file_name = path + "log.csv"

    with open(file_name, "w") as f:
        while True:
            character = ser.read().decode()
    
            if character == "\n":
                print(serial_msg)
                f.write(serial_msg+character)
                msg = ""
            else:
                serial_msg += character

            next_msg = socket.recv(flags=zmq.NOBLOCK)
            if next_msg == "NEXT": # check if moving to next test case
                break

ser.close()
