# zeek-scripts/ml-detector.zeek

# Simple anomaly detection based on traffic patterns
module MLDetector;

export {
    redef enum Notice::Type += {
        ConnectionAnomaly
    };
}

event connection_state_remove(c: connection)
{
    local orig_pkts = c$orig$num_pkts;
    local duration = c$duration;

    # Flag high packet count in short duration (port scan / DDoS pattern)
    if ( orig_pkts > 2 && duration < 5.0 sec )
    {
        NOTICE([$note=ConnectionAnomaly,
                $msg=fmt("Anomalous connection: %d pkts in %.2f sec", orig_pkts, duration),
                $conn=c]);
    }
}