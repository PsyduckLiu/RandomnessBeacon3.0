.PHONY: build clean

BIN_FILE=node

build:
	go build -o "${BIN_FILE}" main.go blankMsgHandler.go errorMsgHandler.go normalMsgHandler.go setupMsgHadler.go variables.go

clean:
	go clean
	rm ${BINARY_NAME}