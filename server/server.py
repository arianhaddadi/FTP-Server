import json
import socket
import threading
import time
import os
import ssl
import base64
import datetime


class User:
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.hasUsageLimit = False
        self.isAdmin = False


class Server:
    
    def __init__(self, configInfo):
        self.users = []
        self.configInfo = configInfo


    def setUsers(self, usersInfo):
        for i in range(len(usersInfo)):
            userInfo = usersInfo[i]
            self.users.append(User(userInfo['user'], userInfo['password']))


    def setLoggingInfo(self, loggingInfo):
        if loggingInfo["enable"]:
            self.loggingPath = os.path.abspath(os.path.join(self.initialDirectory, loggingInfo["path"]))
        else:
            self.loggingPath = None


    def setAccountingInfo(self, accountingInfo):
        if accountingInfo["enable"]:
            self.usageLimitWarningThreshold = accountingInfo["threshold"]
            for userAccountingInfo in accountingInfo["users"]:
                user = self.findUserByUsername(userAccountingInfo["user"])
                user.hasUsageLimit = True
                user.size = int(userAccountingInfo["size"])
                user.email = userAccountingInfo["email"]
                user.alert = userAccountingInfo["alert"]


    def logError(self, logInfo):
        if self.loggingPath is not None:
            logFile = open(self.loggingPath, "a")
            logFile.write(str(datetime.datetime.now()) + ": ERROR " + logInfo + "\n")
            logFile.close()

    
    def logInfo(self, logInfo):
        if self.loggingPath is not None:
            logFile = open(self.loggingPath, "a")
            logFile.write(str(datetime.datetime.now()) + ": INFO " + logInfo + "\n")
            logFile.close()


    def setAuthorizationInfo(self, authorizationInfo):
        if authorizationInfo["enable"]:
            self.hasAuthorizationSystem = True
            for admin in authorizationInfo["admins"]:
                self.findUserByUsername(admin).isAdmin = True
            self.filesWithRestrictedAccess = []
            for file in authorizationInfo["files"]:
                self.filesWithRestrictedAccess.append(os.path.abspath(os.path.join(self.initialDirectory, file)))
        else:
            self.hasAuthorizationSystem = False


    def configure(self):
        self.initialDirectory = os.getcwd()
        self.commandChannelPort = self.configInfo["commandChannelPort"]
        self.dataChannelPort = self.configInfo["dataChannelPort"]
        self.setUsers(self.configInfo["users"])
        self.setLoggingInfo(self.configInfo["logging"])
        self.setAccountingInfo(self.configInfo["accounting"])
        self.setAuthorizationInfo(self.configInfo["authorization"])


    def findUserByUsername(self, username):
        for i in range(len(self.users)):
            if self.users[i].username == username:
                return self.users[i]
        return None


    def handleUsername(self, commandSegments, commandSocket, clientAddress, threadInfo):
        if len(commandSegments) != 1:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") entered a command with wrong syntax.")
        elif threadInfo["user"] is not None or threadInfo["enteredUsernameForLogin"] is not None:
            commandSocket.send("503 Bad sequence of commands.".encode())
            self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") attempted to login while he/she was already loginned or already entered his/her username.")
        else:
            threadInfo["enteredUsernameForLogin"] = commandSegments[0]
            commandSocket.send("331 User name okay, need password.".encode())
            self.logInfo("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") entered a username.")


    def handlePassword(self, commandSegments, commandSocket, clientAddress, threadInfo):
        if len(commandSegments) != 1:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") entered a command with wrong syntax.")
        else:
            if threadInfo["enteredUsernameForLogin"] is not None:
                userWithEnteredUsername = self.findUserByUsername(threadInfo["enteredUsernameForLogin"])
                if userWithEnteredUsername is not None and userWithEnteredUsername.password == commandSegments[0]:
                    commandSocket.send("230 User logged in, proceed.".encode())
                    threadInfo["user"] = userWithEnteredUsername
                    self.logInfo("User '" + userWithEnteredUsername.username + "' logged in!")
                else:
                    commandSocket.send("430 Invalid username or password.".encode())
                    self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") entered wrong authentication info.")
                threadInfo["enteredUsernameForLogin"] = None
            
            else:
                commandSocket.send("503 Bad sequence of commands.".encode())
                self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") attempted to enter password before username.")


    def handlePrintingWorkDirectory(self, commandSocket, threadInfo):
        commandSocket.send(("257 " + threadInfo["currentDirectory"]).encode())
        self.logInfo("User '" + threadInfo["user"].username + "' got his/her current working directory (" + threadInfo["currentDirectory"] + ").")

    
    def accessDenied(self, user, filename):
        return self.hasAuthorizationSystem and user.isAdmin is False and filename in self.filesWithRestrictedAccess

    def makeFile(self, commandSocket, filename, threadInfo):
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        fileAddress = os.path.abspath(os.path.join(currentDirectory, filename))
        if self.accessDenied(user, fileAddress):
            commandSocket.send("550 File unavailable.".encode())
            self.logError("User '" + user.username + "'  attempted to remove a restricted file and was prevented.")
        else:
            try:
                file = open(fileAddress, "x")
                file.close()
                commandSocket.send(("257 " + filename + " created.").encode())
                self.logInfo("File '" + filename + "' was created by user '" + user.username + "'.")
            except:
                commandSocket.send(("500 Error.").encode())
                self.logError("User '" + user.username + "' attempted to create a file but failed.")


    def makeDirectory(self, commandSocket, directoryName, threadInfo):
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        try:
            os.mkdir(os.path.join(currentDirectory, directoryName))
            commandSocket.send(("257 " + directoryName + " created.").encode())
            self.logInfo("Directory '" + directoryName + "' was created by user '" + user.username + "'.")
        except:
            commandSocket.send(("500 Error.").encode())
            self.logError("User '" + user.username + "' attempted to create a directory but failed.")


    def handleMakingDirectoryOrFile(self, commandSegments, commandSocket, threadInfo):
        if len(commandSegments) == 2 and commandSegments[0] == '-i':
            self.makeFile(commandSocket, commandSegments[1], threadInfo)
        elif len(commandSegments) == 1:
            self.makeDirectory(commandSocket, commandSegments[0], threadInfo)
        else:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("User '" + threadInfo["user"].username + "' entered a command with wrong syntax.")


    def removeDirectory(self, commandSocket, directoryName, threadInfo):
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        try:
            os.rmdir(os.path.join(currentDirectory, directoryName))
            commandSocket.send(("250 " + directoryName + " deleted.").encode())
            self.logInfo("Directory '" + directoryName + "' was deleted by user '" + user.username + "'.")
        except FileNotFoundError:
            commandSocket.send(("550 No such file or directory.").encode())
            self.logError("User '" + user.username + "' attempted to delete a non-existing directory.")
        except OSError:
            if os.path.isdir(os.path.join(currentDirectory, directoryName)):
                commandSocket.send(("10066 Directory not empty.").encode())
                self.logError("User '" + user.username + "' attempted to delete a non-empty directory.")   
            else:
                commandSocket.send("500 Error.".encode())
                self.logError("User '" + user.username + "' attempted to delete an existing file with a command for deleting directories.")


    def removeFile(self, commandSocket, filename, threadInfo):
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        fileAddress = os.path.abspath(os.path.join(currentDirectory, filename))
        if self.accessDenied(user, fileAddress):
            commandSocket.send("550 File unavailable.".encode())
            self.logError("User '" + user.username + "' attempted to remove a restricted file and was prevented.")
        else:
            try:
                os.remove(fileAddress)
                commandSocket.send(("250 " + filename + " deleted.").encode())
                self.logInfo("File '" + filename + "' was deleted by user '" + user.username + "'.")
            except:
                commandSocket.send(("500 Error.").encode())
                self.logError("User '" + user.username + "' attempted to delete a directory but failed.")


    def handleRemovingDirectoryOrFile(self, commandSegments, commandSocket, threadInfo):
        if len(commandSegments) == 2 and commandSegments[0] == '-f':
            self.removeDirectory(commandSocket, commandSegments[1], threadInfo)
        elif len(commandSegments) == 1:
            self.removeFile(commandSocket, commandSegments[0], threadInfo)
        else:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("User '" + threadInfo["user"].username + "' entered a command with wrong syntax.")

    def setupDataConnection(self, clientToken):
        while True:
            dataSocket = self.dataSocket.accept()[0]
            acceptedCLientToken = dataSocket.recv(8).decode()
            if acceptedCLientToken == clientToken:
                dataSocket.send("OK".encode())
                dataSocket.recv(8)
                return dataSocket
            else:
                dataSocket.send("Error".encode())
                dataSocket.close()

    def sendData(self, data, clientToken):
        dataSocket = self.setupDataConnection(clientToken)
        if type(data) is str:
            data = data.encode()
        i = 0
        while i < len(data):
            dataSocket.sendall(data[i:i+2048])
            dataSocket.recv(8)
            i += 2048
        dataSocket.send("done".encode())
        dataSocket.close()


    def handleListingAllFilesInADirectory(self, commandSocket, threadInfo): 
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        
        allFilesListResponse = ""
        allFilesInCurrentDirectory = os.listdir(currentDirectory)
        for file in allFilesInCurrentDirectory:
            if not self.accessDenied(user, os.path.join(currentDirectory, file)):
                allFilesListResponse += (file + '\n')

        self.sendData(allFilesListResponse, threadInfo["clientToken"])
        commandSocket.send("226 List transfer done.".encode())
        self.logInfo("User '" + user.username + "' Got all Files in his/her current directory which he/she had access to(" + str(allFilesInCurrentDirectory) + ").")


    def handleChangingDirectory(self, commandSegments, commandSocket, threadInfo):
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        if len(commandSegments) == 0:
            threadInfo["currentDirectory"] = self.initialDirectory
            commandSocket.send(("250 Successful Change.").encode())
            self.logInfo("User '" + user.username + "' changed its working directory to server's initial directory(" + self.initialDirectory + ").")
        elif len(commandSegments) == 1:
            directory = commandSegments[0]
            newDirectory = os.path.abspath(os.path.join(currentDirectory, directory))
            if os.path.exists(newDirectory):
                threadInfo["currentDirectory"] = newDirectory
                commandSocket.send(("250 Successful Change.").encode())
                self.logInfo("User '" + user.username + "' changed its working directory to " + self.initialDirectory + ".")
            else:
                commandSocket.send(("550 No such file or directory.").encode())
                self.logError("User '" + user.username + "' attempted to change its directory to non-existing directory.")
        else:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("User '" + user.username + "' entered a command with wrong syntax.")


    def readFileAndCalculateSize(self, fileAddress):
        fileSize = os.path.getsize(fileAddress)
        file = open(fileAddress, "rb")
        fileContent = file.read()
        file.close()
        return fileContent, fileSize


    def sendAlertEmail(self, user): 
        alert = "Your usage Limit became " + str(user.size) + " which is less than our ftp server's usage threshold to warn the user which is " + str(self.usageLimitWarningThreshold) + "."
        endOfDataIdentifier = "\r\n.\r\n"
        mailServer = "mail.ut.ac.ir"


        mailSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mailSocket = ssl.wrap_socket(mailSocket)
        mailSocket.connect((mailServer, 465))
        response = mailSocket.recv(1024).decode()
        if response[:3] != "220":
            raise Exception("220 reply not received from server.")


        mailSocket.send("EHLO localhost\r\n".encode())
        response = mailSocket.recv(1024).decode()
        if response[:3] != "250":
            raise Exception("250 reply not received from server.")


        username = "Aryan.haddadi1378"
        password = "Aryan13461378"
        base64EncodedAuthInfo = base64.b64encode(("\x00" + username + "\x00" + password).encode())
        authInfo = "AUTH PLAIN ".encode() + base64EncodedAuthInfo + "\r\n".encode()
        mailSocket.send(authInfo)
        response = mailSocket.recv(1024)
        

        mailSocket.send("MAIL FROM: <aryan.haddadi1378@ut.ac.ir>\r\n".encode())
        response = mailSocket.recv(1024).decode()
        if response[:3] != "250":
            raise Exception("250 reply not received from server.")


        mailSocket.send(("RCPT TO: <" + user.email + ">\r\n").encode())
        response = mailSocket.recv(1024).decode()
        if response[:3] != "250":
            raise Exception("250 reply not received from server.")


        mailSocket.send("DATA\r\n".encode())
        response = mailSocket.recv(1024).decode()
        if response[:3] != "354":
            raise Exception("250 reply not received from server.")


        mailSocket.send("From: <ftpServer>\r\n".encode())
        mailSocket.send("Subject: Alert\r\n".encode())
        mailSocket.send(("to: " + user.email + "\r\n").encode())
        mailSocket.send(alert.encode())
        mailSocket.send(endOfDataIdentifier.encode())
        response = mailSocket.recv(1024).decode()
        if response[:3] != "250":
            raise Exception("250 reply not received from server.")


        mailSocket.send("QUIT\r\n".encode())
        response = mailSocket.recv(1024).decode()

        mailSocket.close()



    def handleFileDownload(self, commandSegments, commandSocket, threadInfo): 
        user, currentDirectory = threadInfo["user"], threadInfo["currentDirectory"]
        if len(commandSegments) != 1:
            commandSocket.send("501 Syntax error in parameters or arguments.".encode())
            self.logError("User '" + user.username + "' entered a command with wrong syntax.")
        else:
            filename = commandSegments[0]
            fileAddress = os.path.abspath(os.path.join(currentDirectory, filename))
            if self.accessDenied(user, fileAddress):
                commandSocket.send("550 File unavailable.".encode())
                self.logError("User '" + user.username + "' attempted to download a restricted file and was prevented.")
                self.sendData("No Data", threadInfo["clientToken"])
            else:
                try:
                    fileContent, fileSize = self.readFileAndCalculateSize(fileAddress)
                    if user.hasUsageLimit and user.size < fileSize:
                        commandSocket.send(("425 Can't open data connection.").encode())
                        self.logError("User '" + user.username + "' couldn't download his/her desired file due to his/her usage limit.")
                        self.sendData("No Data", threadInfo["clientToken"])
                    else:
                        if user.hasUsageLimit:
                            user.size -= fileSize
                            if user.alert and user.size < self.usageLimitWarningThreshold:
                                try:
                                    self.sendAlertEmail(user)
                                    self.logInfo("User '" + user.username + "' was alerted about reaching his usage limit below threshold.")
                                except Exception as error:
                                    print("Error In Sending e-mail:", error)
                                    self.logError("Failed to alert user '" + user.username + "' for reaching his/her usage limit below threshold.")
                        self.sendData(fileContent, threadInfo["clientToken"])
                        commandSocket.send("226 Successful Download.".encode())
                        self.logInfo("User '" + user.username + "' successfully downloaded file '" + filename + "'.")
                except FileNotFoundError:
                    commandSocket.send(("550 No such file or directory.").encode())
                    self.logError("User '" + user.username + "' attempted to download a non-existing file.")
                    self.sendData("No Data", threadInfo["clientToken"])


    def handleHelp(self, commandSocket, threadInfo):
        commandsHelpText = "214\n"
        commandsHelpText += "USER [name], Its argument is used to specify the user's string. It is used for user authentication.\n"
        commandsHelpText += "PASS [password], Its argument is used to specify the user's password. It is used for user authentication.\n"
        commandsHelpText += "PWD, It is used for printing server's current working directory\n"
        commandsHelpText += "MKD [flag] [name], Its argument is used to specify the file/directory path. It is used for creating a new file or directory. Use -i flag if you want a file to be created.\n"
        commandsHelpText += "RMD [flag] [name], Its argument is used to specify the file/directory path. It is used for removing a file or directory. Use -f flag if you want a directory to be removed.\n"
        commandsHelpText += "LIST, It is used for printing list of file/directories that exist in current working directory\n"
        commandsHelpText += "CWD [path], Its argument is used to specify the directory's path. It is used for changing server's current working directory.\n"
        commandsHelpText += "DL [name], Its argument is used to specify filename. It is used for downloading a file from server.\n"
        commandsHelpText += "HELP, It is used for printing a list of all available commands and their description.\n"
        commandsHelpText += "QUIT, It is used for logging out from the server.\n"
        commandSocket.sendall(commandsHelpText.encode())
        self.logInfo("User '" + threadInfo["user"].username + "' successfully received commands help.")


    def handleQuit(self, commandSocket, threadInfo):
        user = threadInfo["user"]
        threadInfo["user"], threadInfo["currentDirectory"] = None, self.initialDirectory
        commandSocket.send(("221 Successful Quit.").encode())
        self.logInfo("User '" + user.username + "' successfully logged out.")


    def parseCommand(self, command, commandSocket, clientAddress, threadInfo):
        commandSegments = command.split()
        if commandSegments[0] == "USER":
            self.handleUsername(commandSegments[1:], commandSocket, clientAddress, threadInfo)
        elif commandSegments[0] == "PASS":
            self.handlePassword(commandSegments[1:], commandSocket, clientAddress, threadInfo)
        else:
            if threadInfo["user"] is None:
                commandSocket.send("322 Need account for login.".encode())
                self.logError("CLient(" + str(clientAddress[0]) + ", " + str(clientAddress[1]) + ") attempted to enter a command before logging in.")
            else:
                if commandSegments[0] == "PWD":
                    self.handlePrintingWorkDirectory(commandSocket, threadInfo)
                elif commandSegments[0] == "MKD":
                    self.handleMakingDirectoryOrFile(commandSegments[1:], commandSocket, threadInfo)
                elif commandSegments[0] == "RMD":
                    self.handleRemovingDirectoryOrFile(commandSegments[1:], commandSocket, threadInfo)
                elif commandSegments[0] == "LIST":
                    self.handleListingAllFilesInADirectory(commandSocket, threadInfo)
                elif commandSegments[0] == "CWD":
                    self.handleChangingDirectory(commandSegments[1:], commandSocket, threadInfo)
                elif commandSegments[0] == "DL":
                    self.handleFileDownload(commandSegments[1:], commandSocket, threadInfo)
                elif commandSegments[0] == "HELP":
                    self.handleHelp(commandSocket, threadInfo)
                elif commandSegments[0] == "QUIT":
                    self.handleQuit(commandSocket, threadInfo)
                else:
                    commandSocket.send("502 Command not implemented.".encode())
                    self.logError("User " + threadInfo["user"] + "entered a non-available command.")


    def communicateWithCLient(self, commandSocket, clientAddress):
        clientToken = str(clientAddress[1])
        commandSocket.send(clientToken.encode())
        threadInfo = {"user":None, "enteredUsernameForLogin":None, "currentDirectory":os.getcwd(), "clientToken":clientToken}
        while True:
            command = commandSocket.recv(1024).decode()
            if command == "":
                commandSocket.close()
                print("A client closed its connection.")
                break
            self.parseCommand(command.strip(), commandSocket, clientAddress, threadInfo)


    def run(self):
        self.configure()

        self.commandSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.commandSocket.bind(("", self.commandChannelPort))
        self.commandSocket.listen(10)

        self.dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dataSocket.bind(("", self.dataChannelPort))
        self.dataSocket.listen(10)

        print("Server is ready.")
        while True:
            commandSocket, clientAddress = self.commandSocket.accept()
            threading.Thread(target=self.communicateWithCLient, args=([commandSocket, clientAddress])).start()



if __name__ == "__main__":
    try:
        configFile = open("config.json")
        configInfo = json.load(configFile)
        configFile.close()

        server = Server(configInfo)
        server.run()
    except FileNotFoundError:
        print("Config File Not Found.")
