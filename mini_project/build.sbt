// Définir la version de Scala
scalaVersion := "2.13.12"

// Informations sur le projet
name := "mini_project"
organization := "ch.epfl.scala"
version := "1.0"

// Dépendances du projet
libraryDependencies ++= Seq(
  "org.scala-lang.modules" %% "scala-parser-combinators" % "2.3.0",
  "com.softwaremill.sttp.client3" %% "core" % "3.9.0",
  "org.json4s" %% "json4s-jackson" % "4.0.6", // Correcte la dépendance pour utiliser `jackson`
  "org.mongodb" % "mongodb-driver-sync" % "4.9.0"
)

// Résolution des dépendances
ThisBuild / resolvers += "Maven Central" at "https://repo1.maven.org/maven2/"
