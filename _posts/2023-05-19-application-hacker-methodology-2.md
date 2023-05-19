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
* Manually visit each online domain 
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

#### Tip \#1: Skip Content Management Systems (CMS), Blogs, & News

Unless you are testing for specific known bugs such as the Elementor DOM XSS, xmlrpc, or drupaggedon, I would avoid testing a CMS such as Wordpress, Drupal, AEM, or Joomla. The majority of the content you tend to find on these systems is static in nature and while they are great tools for distributing static content, they are pretty hardened these days. 

As you go through your online assets, use [**Wappalyzer**](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/) to help you identify common CMS sites. If you find a particularly older CMS (>1 year out of date), there may be an unpatched vulnerability and it is usually worth a `nuceli -as -u http://cmssite.com` or a wpscan for Wordpress. Wordpress makes it easy to keep plugins up to date, so finding older Wordpress is uncommon.

#### Tip \#2: Find Patterns in Asset Site Titles

It is unlikely that a large organization will write unique code for each asset they expose to the internet. When scanning across large organizations, you will start to see patterns in titles and 
content lengths from your Httpx scan. As you visit sites within your target scope, take note of common layouts and navigation systems. If you stumble upon a custom static site, there are likely more 
sites using the same code base. Let's say you find a custom static site with a title like "subdomain.target.com Blog" and a content length of around 43000. You can use grep and anew to filter these sites:

```sh
cat online-asset-titles.txt | grep -Ev "\.target.com Blog|403[0-9][0-9]|Wordpress" | anew online-asset-titles-no-blogs.txt
```

As you discover more static assets, add these patterns to your grep line to keep filtering out noise and help you find useful assets.


![Shodan Query](/assets/shodan-query.JPG)


```sh
# Generate and brute force new domains based on pre-discovered domains. 
cat domains | dnsgen - | massdns -r ~/resolvers.txt -t A -o L --flush 2>/dev/null | anew dns-gen-domains
cat dns-gen-domains | anew domains && rm -f dns-gen-domains
```



### Conclusion 

Our goal in this phase was to give ourselves a decent attack surface. This is probably the most widely covered phase within the web application testing realm and is by far the easiest. 

Once you have a sufficient number of endpoints to examine, you will want to move into the next phase: Identifying Data Entry Points. We will take interesting sites and strive to fully understand the application and frameworks involved. Once we understand the access controls, we can examine them for flaws.

This phase will be documented in the Application Hacking Methodology Part 2. 
