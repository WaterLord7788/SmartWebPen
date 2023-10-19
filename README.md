<h1 align="center">Welcome to SmartWebPen 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000" />
  <a href="https://github.com/WaterLord7788/SmartWebPen#readme" target="_blank">
    <img alt="Documentation" src="https://img.shields.io/badge/documentation-yes-brightgreen.svg" />
  </a>
  <a href="https://github.com/kefranabg/readme-md-generator/graphs/commit-activity" target="_blank">
    <img alt="Maintenance" src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" />
  </a>
  <a href="https://github.com/WaterLord7788/SmartWebPen/blob/main/LICENSE" target="_blank">
    <img alt="License: GNU General Public License v3.0" src="https://img.shields.io/github/license/WaterLord7788/SmartWebPen" />
  </a>
  <a href="https://twitter.com/KristianPivine1" target="_blank">
    <img alt="Twitter: KristianPivine1" src="https://img.shields.io/twitter/follow/KristianPivine1.svg?style=social" />
  </a>
</p>

> Easy web application penetration testing framework. Automation made simple.

### 🏠 [Homepage](https://github.com/WaterLord7788/SmartWebPen#readme)

## Install

<b>Step 1 (optional)</b>
```sh
# Command below is not necessary but can be performed for 
# a lot more smoother experience during the first start.
python website/installation.py
```

<b>Step 2</b>

###### In file `website/__init__.py`, you can change various settings, such as:

```python
# If you want to make application more stable, disable the setting below by setting the value to `False`.
GENERATE_SECRET_KEY_ON_RESTART = True
SECRET_KEY = 'YOUR-ULTRA-RANDOM-SECRET-KEY-1337' # Set secure secret key, if auto-generation of secret keys is disabled. 

ADMIN = "admin@localhost.com" # Email authorized to directly run debugging functionalities, if value below is set to `True`.
DEBUG_ENABLED = False         # Disable for additional security - disables command execution in `/debug`.
SIGNUP_ENABLED = True         # Disable if you do not want signup to be accessible.

# This is for developers.
# If you want to see general logging messages, such as: 127.0.0.1 - - [15/Feb/2013 10:52:22] "GET /index.html HTTP/1.1" 200
# then go ahead and replace `True` to `False`.
GENERAL_LOGGING_DISABLED = False

# Screenshotting and ping functionality settings below.
SCREENSHOT_DELAY_SECONDS = 1 # Increase the delay if getting no responses from alive targets.
PING_COUNT_NUMBER = 1        # Increase the number if you want to get more accurate results.
```

<b>Step 3</b>
```sh
# Run the service.
python main.py
```

<b>Step 4</b>
```http
# Open the link below to access the service via a web browser.
http://127.0.0.1:5000/
```


## Tools used
The following tools are being used in this framework:
* [Amass](https://github.com/owasp-amass/amass) - automating asset discovery
* [Waybackurls](https://github.com/tomnomnom/waybackurls) - gathering past URLs
* [BGP.HE.NET](BGP.HE.NET) - amazing variety of online tools :D
* [Gau](https://github.com/lc/gau) - gathering past URLs
* [Subfinder](https://github.com/projectdiscovery/subfinder) - automating asset discovery
* [Crt.sh](https://crt.sh/) - automating asset discovery
* [Httpx](https://github.com/projectdiscovery/httpx) - discovering live targets
* [Dalfox](https://github.com/hahwul/dalfox) - automating security assesment
* [Gf](https://github.com/tomnomnom/gf) - pinpointing peculiar endpoints
* [Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) - patterns for pinpointing peculiar endpoints
* [Dnsx](https://github.com/projectdiscovery/dnsx)
* [eyewitness](https://github.com/RedSiege/EyeWitness) - screenshotting
* [AS converter](https://gist.github.com/sanderfoobar/6d98bcad533855b1b81b7fdd4e04930e) - converting AS numbers to IP ranges
* [prips](https://gitlab.com/prips/prips) - converting IP ranges to IPs

## Additional information
The framework will **automatically try to install all required tools**, so you don't have to do it yourself. Sit back and relax as this tool will do everything for you during the first startup!


## Author

👤 **Kristian Päivinen**

* Twitter: [@KristianPivine1](https://twitter.com/KristianPivine1)
* GitHub: [@WaterLord7788](https://github.com/WaterLord7788)

## 🤝 Contributing

**Thank you** for everyone contibuting to this awesome project!
- **Niyaz Ahmed Khan** for contributing in recon - [LinkedIn](https://www.linkedin.com/in/niyaz-khan-093867267)
- **Sander** at **sander@cedsys.nl** for developing a great tool to automate process of converting AS numbers to IPs - [GitHub](https://gist.github.com/sanderfoobar)


Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/WaterLord7788/SmartWebPen/issues). 

## Show your support

Give a ⭐️ if this project helped you!

## 📝 License

Copyright © 2023 [Kristian Päivinen](https://github.com/WaterLord7788).<br />
This project is [GNU General Public License v3.0](https://github.com/WaterLord7788/SmartWebPen/blob/main/LICENSE) licensed.

***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_