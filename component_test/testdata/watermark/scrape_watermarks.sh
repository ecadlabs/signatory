#!/bin/sh
#2023-03-31T23:35:31Z
while true; do
    d=`date +%F-%T-%Z`
    docker exec -it signatory cat /var/lib/signatory/watermark/NetXo5iVw1vBoxM.json > ./scraped_data/$d.watermark.json
    sleep 1
done

