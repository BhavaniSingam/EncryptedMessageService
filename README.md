# EncryptedMessageService
## An encrypted message service using PGP

### Collaborators
  - Brian Mc George
  - Michael Kyeyune
  - Thandile Xiphu
  - William Lumala
 
### Requirements
  - Java 8
  - Maven *(if building project)*

### Important Notice
The jar needs to be called from the root directory of the project as it references files within the project using a relative path.

### Running this project
Pre compiled client and server jars have been made available and are at the root directory, they can be run as follows:
  - Execute the jars from terminal as debug messages are printed to standard output:
    - ```java -jar ClientEncryptedChat-jar-with-dependencies.jar```
    - ```java -jar ServerEncryptedChat-jar-with-dependencies.jar```
  - Ensure the server is listening at the desired IP then use the client to connect to the desired IP

### Building this project
This project uses maven to manage dependencies and building. <br>
Run the following from the root of this project to compile and package the jars for this project:
  - ```mvn clean compile```
  - Move the two jars created outside target to the root directory *(as it currently relies on some files that are set with relative paths from the root of this project)*
  - Execute the jars from terminal as debug messages are printed to standard output:
    - ```java -jar ClientEncryptedChat-jar-with-dependencies.jar```
    - ```java -jar ServerEncryptedChat-jar-with-dependencies.jar```
