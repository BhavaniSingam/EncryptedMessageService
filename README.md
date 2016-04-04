# EncryptedMessageService
## An encrypted message service using PGP

### Collaborators
  - Brian Mc George
  - Michael Kyeyune
  - Thandile Xiphu
  - William Lumala
 
### Building this project
This project uses maven to manage dependencies and building. <br>
Run the following from the root of this project to compile and package the jars for this project:
  - ```mvn clean compile```
  - Move the two jars created outside target to the root directory
  - Execute the jars from terminal as debug messages are printed to standard output: ```java -jar ClientEncryptedChat-jar-with-dependencies.jar``` / ```java -jar ServerEncryptedChat-jar-with-dependencies.jar```
