run:
	mvn clean package
	java -jar target/dependency-updater-mcp-0.0.1-SNAPSHOT.jar

run-demo:
	mvn clean package
	java -Ddemo.failNextBuild=true -jar target/dependency-updater-mcp-0.0.1-SNAPSHOT.jar
