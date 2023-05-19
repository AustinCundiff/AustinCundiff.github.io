---
layout: default
title:  "Application Hacking Part 2: Identifying Entry Points"
date:   2023-05-19 11:02:21 +0100
author: Sysdum
---

## Application Hacker Methodology Part 2: Identifying Entry Points

### Introduction

In the recon section, we discussed mapping an organization's attack surface, which lines up with Step 1 in [Lockheed's Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) and Step's 1 & 2 in [Jason Haddix's Bug Hunter Methodology](https://github.com/jhaddix/tbhm). 
Depending on the size of the scope, this can be possibly thousands of URLS, site titles, and link dumps, which can be quite daunting. In order to make sense of all this data, we must learn what we can ignore 
and also learn where an attack is even possible to begin with. The majority of critical bugs in the wild stem from some kind of data entry point. Examples of data entry points include form submissions, queries, account creation/modification, or uploading files. 
The reason why these entry points are so important is because they provide a window to server-side code and back-end systems. It is here where the more important vulnerabilities live.

In this guide, I hope to highlight some common pitfalls when approaching a target scope as well as provide some tips for finding entry points.

### Roadmap
- Filtering Out the Noise 🎧
- Determining the Technology Stack 🖧
- Finding Interesting Entry Points 🚪


## Filtering Out the Noise

### Our Goals for this phase

* Find and remove static assets that are unlikely to provide us a way of interacting in a meaningful way
* Curate a list of interesting assets to examine

Pre-requisites from the recon phase:
- List of active domains
- URLs from spidering & online archivers
- List of titles from online domains

*Tools used:*: [**Anew**](https://github.com/tomnomnom/anew), [**httpx**](https://github.com/projectdiscovery/httpx), [**Wappalyzer**](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/), grep

### Weeding out Static Sites

Many bug hunters and web application testers often run into a wall after the recon phase. This is in part due to there not being a deterministic method to finding interesting assets. As you gain experience, you will 
develop a sense for what to ignore and what to target. However, during the first few months of testing against production environments, it is easy to get lost in the sauce. 

#### Tip \#1: Skip Content Management Systems (CMS)

Unless you are testing for specific known bugs such as the Elementor DOM XSS, xmlrpc, or drupaggedon, I would avoid testing a CMS such as Wordpress, Drupal, AEM, or Joomla. The majority of the content you tend to find on these 
systems is static in nature. They are great tools for distributing static content and are pretty hardened these days. However, there are not usually entry points for you to get payloads to server-side code. 



![Shodan Query](/assets/shodan-query.JPG)


```sh
# Generate and brute force new domains based on pre-discovered domains. 
cat domains | dnsgen - | massdns -r ~/resolvers.txt -t A -o L --flush 2>/dev/null | anew dns-gen-domains
cat dns-gen-domains | anew domains && rm -f dns-gen-domains
```

Choose one: [**Feroxbuster**](https://github.com/epi052/feroxbuster) | [**Ffuf**](https://github.com/ffuf/ffuf) | [**Gobuster**](https://github.com/OJ/gobuster) | [**Turbo** Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)

* [**httpx**](https://github.com/projectdiscovery/httpx)
* [**Wappalyzer**](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
* [**Waybackurls**](https://github.com/tomnomnom/waybackurls)
* [**gospider**](https://github.com/jaeles-project/gospider)
* [**uro**](https://github.com/s0md3v/uro)

There are a couple of methods to help guide our discovery phase from here:
  * Screenshot all endpoints using eyewitness or gowitness, then review screenshots for interesting applications.
    * Slower and a pain to manually review 
  * Grab titles and content lengths to get a basic idea of what an endpoint is hosting.
    * Faster but not as accurate as seeing the page 

I prefer using httpx to grab titles so that I can filter out uninteresting endpoints using grep. Below is an httpx line to gather site titles.
```sh
cat online-hosts | httpx -rl 50 -retries 3 -timeout 7 -random-agent -follow-redirects -nc -cl -title | anew titles
```
There are a lot of options in this snippet, so I'll break it down:
* rl : rate-limit aka requests per second. Keep it reasonable (or don't I'm not a cop)
* retries : how many times it will retry the resource. I've seen this prevent false negatives, especially if you're going with a high request rate. 
* timeout : the default is 5 seconds, but I like to increase it because some old servers are slow
* random-agent : randomizes the user agent string to prevent some firewalls from flagging us
* follow-redirects : Follow a redirect from / to /endpoint so we can retrieve the title for what we care about
* nc : no color. This will save us headaches when grepping through the output. If you like pretty colors, take this off.
* cl : content-length. WAFs will usually return a static content length when a resource is blocked, so this lets us filter those endpoints out.
* title : Grabs the title of the endpoint. 
* sc : (optional) Display status-code e.g. 200,403,500. Can be useful in certain environments. However, status codes don't mean a whole lot these days. Many apps return a 200 and then the content is `resource not found`. If you develop apps and do this, please stop hurting me.

All of these together will result in the following list of titles and content lengths:

![Shodan Query](/assets/httpx.png)

> Note: Most of the tools used below can be configured to output in JSON. Feel free to substitute grep and vim with your text editor of choice. The idea is that we can easily filter out the junk with negative searches like egrep -v.

Now it's time to go through our output. Depending on the number of endpoints, this could be large. I prefer to open the results in vim, but you can also page through it with less or another text editor like vscode or sublime.

```sh
cat titles | less
# or use vim
vim titles
```

As you go through them, you will see similar titles and content lengths. For example, let's say your organization has 30 different static blogs. You can use egrep to filter the blog title `egrep -v "blog title" titles | less` or use vim `%! egrep -v blog-title`. I will also usually see the same site hosted for different countries such as au.example.com uk.example.com, etc. The content length and title should generally be the same and you can use the same filter tricks to remove the junk.

Here are the titles I'm usually interested in:
- Not found --> Usually indicates something is being hosted but without a redirect from the web root.
- Forbidden --> Occasionally has paths accessible that may be incorrectly configured and reveal sensitive information.
- Sensitive title --> Titles that indicate sensitive information is stored on the application (SSN / billing / corp)
- Esoteric technology banner --> Don't recognize the server? It's probably old and busted.
- Internal / Corp / File upload related titles 

> Note: Often a WAF or CDN will return a 200 with a static title or content length for restricted resources. The title and content length returned by httpx provides an easy avenue to filter out these responses and narrow our attention to applications we can interact with.

### Gathering URLs from interesting domains

Instead of immediately launching into forced browsing (i.e. brute forcing directories), the majority of application data entry points can be discovered via URL gathering.

Here we can use gau (Get All Urls) and waybackurls to pull from the Waybackmachine and AlienVault's open threat exchange.
```sh
echo example.com | gau | anew urls
echo example.com | waybackurls | anew urls
```
Then you want to spider the site itself for URLs
```sh
gospider -d 5 -s example.com -q -t 10 -o .
cat example.com-urls | anew urls
```
This will result in a text file with a ton of links. Many of these will be garbage such as font or image files. Remember, we're looking for places that accept input, so static assets are generally of no interest.

First I grab all queries such as `/endpoint?file=example.jpg` which are typically the bulk of our data entry points. Uro is a tool that will remove duplicate queries such as `/endpoint?file=example.png`. We already have the first query and don't really care about additional file names being returned, especially if it's something like doc1.xlsx and doc2.xsls etc.
```sh
egrep "\?" urls | uro | anew query-urls
```
Next, I clean out the static assets and the query stings to a separate file to view potentially sensitive directories
```sh
egrep -vi "\?|\.pdf|\.jpg|\.gif|\.png|\.gif|\.doc|\.ttf|\.woff|\.svg|\.eof|\.css|\.eot|\.xls" urls | anew non-query-urls
```


Each URL file is useful in a different way. We have query strings to look at, but we also want to be aware of api interfaces that may accept post requests over get parameters. 

I spend a good amount of time from here reviewing the output on each url file. Here are some things to look for:
* proxy endpoints that accept URL parameters (e.g. proxy.ashx?url=http://example.com) --> Server-side Request Forgery
* Parameters with sequential values (e.g. id=1,2,3,4) --> Insecure Direct Object Reference / Access Control Issues
* Older extensions such as .asp or .nsf --> Generally more likely to be unpatched. Where there's smoke there's fire.
* Backups .old, .zip, .tar.gz , .tar.bz2 --> Credentials, Sensitive Data
* APIs documentation or API endpoints in general
  * Not all APIs are intended to be interacted with directly by a user and can reveal sensitive information or allow an attacker to perform unintended actions

If you find something interesting, skip the content discovery for now. You can and should return to this phase if you hit a wall when testing. 

### Forced Browsing

However, If we strike out with the URLS, then we go with forced browsing. We will need a wordlist first. Here are a couple of different wordlists repositories we can use:
* [**The ultimate wordlist repo: SecLists**](https://github.com/danielmiessler/SecLists)
* [**Assetnote has some excellent wordlists as well**](https://wordlists.assetnote.io/)

For now, we will stick with a directory brute force with a basic raft list 
```sh
feroxbuser -w ~/git/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://example.com/ -A -k -r -d 4 -L 2 -o example.com-dump
```
Let's break down the command:
* -w --> specify a wordlist to use. If the first line in the wordlist is apples it will request example.com/apples
* -u --> the url we want to browse e.g. example.com/
* -A --> Random user-agent
* -k --> Insecure TLS --> Often necessary because if an endpoint is old and forgotten, it probably has expired certs.
* -r --> Follow redirects
* -d 4--> depth 4 --> If feroxbuster discovers a directory, it will start another scan using the same list up to a depth of 4.
* -L 2 --> Limit 2 scans at once --> prevents us crashing the application (hopefully). May need to reduce to 1. 
* -o example.com-dump --> dump the output of the scan to a file

You can pause the scan at any time by hitting enter. You can add custom filters or cancel scans and then resume the scan. 

![Ferox Pause](/assets/pause-menu.png)

Additionally, if you ctrl-c the scan you can use `--resume-from SATE_FILE` to pick up where you left off.

![Ferox results](/assets/ferox-save-state.png)

Now that we have some directories, we hopefully have a lead on some parts of the application that were not intended for us. Examples of these types of directories would be:
* Admin consoles
* Tomcat manager
* Monitoring interface
* Logging directory
* Uploads
* Services allowing us to query data sets e.g. Apache Solr, graphql, elastic

Strangely enough, I have found each of these at least once using a simple wordlist on an endpoint with "Not Found" at the webroot. 

Once you have a list of directories and have identified the technology (i.e. .NET, Java, PHP, Node, REST API, CMS), you want to move to a file-based wordlist for each of the directories. There is no point using a php wordlist on a .NET site, so try to be deliberate when fuzzing for files. 

In this example, we are fuzzing for aspx files in the app directory. This will not recurse (via -n) because we don't want to request something like `example.com/app/loader.aspx/help.aspx` 
```sh
feroxbuser -w ~/git/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u https://example.com/app -A -k -r -n -L 2 -x aspx -o example.com-app-files-dump
```

At this point, it's rinse and repeat of fuzzing for directories and then fuzzing for files. If you're working on a restful API, then substitute files with API actions. This is due to APIs generally not being extension-based. I usually use a generic word-based list here or you can reuse an API-specific list from SecLists or Assetnote.  


>Note: It is often good practice to repeat your reconnaissance periodically as you will often discover new endpoints as time goes on.

### Conclusion 

Our goal in this phase was to give ourselves a decent attack surface. This is probably the most widely covered phase within the web application testing realm and is by far the easiest. 

Once you have a sufficient number of endpoints to examine, you will want to move into the next phase: Identifying Data Entry Points. We will take interesting sites and strive to fully understand the application and frameworks involved. Once we understand the access controls, we can examine them for flaws.

This phase will be documented in the Application Hacking Methodology Part 2. 
