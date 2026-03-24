#!/bin/bash

# Configuration
PORT=8080
LOG_FILE="server.log"
WAIT_SECONDS=10

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Integration Test Automation ===${NC}"

# 1. Cleanup existing processes on PORT
echo -e "Cleaning up port $PORT..."
PID=$(lsof -ti :$PORT)
if [ -n "$PID" ]; then
    echo "Killing process $PID..."
    kill -9 $PID
fi

# 2. Reset environment
echo -e "Resetting environment..."
rm -f "$LOG_FILE" cookies.txt
redis-cli flushdb > /dev/null 2>&1 || echo -e "${YELLOW}[WARN]${NC} Redis not reachable or flushdb failed"

# 3. Start server
echo -e "Starting server with MFA_TEST_MODE=true..."
export MFA_TEST_MODE=true
# Use grep to export .env vars if file exists
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

nohup go run . > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo -en "Waiting for server to start ($WAIT_SECONDS seconds)..."
for i in $(seq 1 $WAIT_SECONDS); do
    sleep 1
    echo -n "."
done
echo -e "\n"

# 4. Check if server started successfully
if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${RED}[ERROR]${NC} Server failed to start. Check $LOG_FILE for details."
    exit 1
fi

if ! curl -s "http://localhost:$PORT/health" > /dev/null && ! curl -s -X POST "http://localhost:$PORT/auth/login" > /dev/null; then
    echo -e "${RED}[ERROR]${NC} Server started but is not responding on port $PORT."
    cat "$LOG_FILE"
    kill $SERVER_PID
    exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} Server is up and running."

# 5. Run tests
echo -e "Running integration tests..."
./test_integration.sh "http://localhost:$PORT"
TEST_RESULT=$?

# 6. Cleanup
echo -e "\n${CYAN}=== Cleanup ===${NC}"
echo "Shutting down server (PID $SERVER_PID)..."
kill $SERVER_PID

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED SUCCESSFULLY!${NC}"
else
    echo -e "${RED}TESTS FAILED!${NC}"
fi

exit $TEST_RESULT
