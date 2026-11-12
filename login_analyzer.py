# Project 02 - Failed Login Attempt Analyzer
# Purpose: Analyze login attempt records to identify failed logins and detect repeated or 
# suspicious login activity.


def log_analyzer(filename):

    total_attempts = 0
    successful_logins = 0
    failed_logins = 0
    failed_attempts_by_ip = {}
    alerts = []
    failed_login_threshold = 3

    file1 = open(filename, "r")
    for line in file1:
        total_attempts += 1
        clean_line = line.strip() #using .strip() to eliminate white spaces
        parts = clean_line.split(",") #using .split() to print a list with 4 items
        timestamp = parts[0]
        ip_address = parts[1]
        username = parts[2]
        status = parts[3]
    
        
        if status == "SUCCESS":
            successful_logins += 1
        elif status == "FAILED":
            failed_logins += 1
        else:
            pass

        if status == "FAILED":
            if ip_address in failed_attempts_by_ip:
                failed_attempts_by_ip[ip_address] += 1
            else:
                failed_attempts_by_ip[ip_address] = 1

        #print(parts)
        #print("Timestamp:", timestamp)
        #print("IP Address:", ip_address)
        #print("Username:", username)
        #print("Status:", status)
        #print("-" * 40)
    #print(file1.read())

    #print("-" * 23 + " LOG RESULTS " + "-" * 23)

    #print("Total Login Attempts:", total_attempts)
    #print("Successful Logins:", successful_logins)
    #print("Failed Logins:", failed_logins)
    #print(failed_attempts_by_ip)

    for key, value in failed_attempts_by_ip.items():
        #print(f"{key}, {value} -> failed attempts")
    
        if value >= 5:
            alerts.append(f"CRITICAL! Suspicious IP -> {key} | Failed Attempts: {value}")
            #print(f"CRITICAL! Suspicious IP -> {key} | Failed Attempts: {value}")
        elif value >= failed_login_threshold:
            alerts.append(f"Warning! Suspicious IP -> {key} | Failed Attempts: {value}")
            #print(f"Warning! Suspicious IP -> {key} | Failed Attempts: {value}")
        else:
            pass

    file1.close()

    return total_attempts, successful_logins, failed_logins, failed_attempts_by_ip, alerts
    
#Calling the functions to scan logs
total, passed_logins, failed, failed_by_ip, al = log_analyzer("login_attemptsPT.1.txt")
#print "al" is just to see if the alerts variable is storing the alerst I have created within
#the if statements above.
#print(al)
#log_analyzer("login_attemptsPT.2.txt")
    
    
def display_results(total, passed_logins, failed, failed_by_ip, al):
    
    print ("-" * 23 + " LOG RESULTS " + "-" * 23)

    print(f"Total Login Attempts: {total}") 
    print(f"Successful Logins: {passed_logins}") 
    print(f"Failed Logins: {failed}")

    print ("-" * 18 + " FAILED ATTEMPTS BY IP " + "-" * 18)

    for IP, count in failed_by_ip.items():
        print(f"IP Address: {IP} | Failed Attempts: {count}")

    print ("-" * 26 + " ALERTS " + "-" * 26)

    for alert in al:
        print(alert)

display_results(total, passed_logins, failed, failed_by_ip, al)

total2, passed_logins2, failed2, failed_by_ip2, al2 = log_analyzer("login_attemptsPT.2.txt")
display_results(total2, passed_logins2, failed2, failed_by_ip2, al2)