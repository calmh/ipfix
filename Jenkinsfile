pipeline {
    agent {
        docker { image 'golang:latest' }
    }

    environment {
        GOPATH=pwd()
    }

    stages {
        stage('Pull') {
            steps {
                dir('src/github.com/calmh/ipfix') {
                    checkout scm
                }
            }
        }

        stage('Test') {
            steps {
                sh 'cd src/github.com/calmh/ipfix && go test'
            }
        }
    }
}