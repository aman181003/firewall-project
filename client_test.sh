while true;do
    curl -s http://192.168.224.6 && echo "Success $(date)" II echo "Failed $(date)"
    sleep 1
done
