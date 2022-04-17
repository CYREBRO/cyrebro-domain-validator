[![Powered by CYREBRO](static_files/CYREBRO_LOGO.png)](https://www.cyrebro.io/)

# CYREBRO's Domain Validator
During an internal development, we noticed that existing domain validation Python packages are not deeply 
validating domains.</br>
Most of the time these packages only check the domain validity using regex, which mostly is not enough. </br>
That is why we at CYREBRO decided to create one that takes a deeper look into domains and provides a more reliable result. </br>

------------------

### Validations
CYREBRO's domain validator checks for:
1. **regex validity** - deep regex, includes a list of known TLDs.
3. **HTTP(/s) availability**.
4. **nslookup**.
5. **whois**.
6. **dkim records**.
7. **spf records**.

------------------

### Installation
##### Through pip
To install the package, simply type:
```
pip install cyrebro-domain-validator
```
##### Through GitHub
Firstly, clone the repository and extract the files. </br>
Export the files and navigate to the directory using the terminal/command line window. </br>
Lastly, once in an activated venv, enter the following command in the terminal/command line window:
###### Windows
```python .\setup.py install```
###### Linux
```python3 ./setup.py install```

##### Dependencies
* [dnspython](https://github.com/rthalley/dnspython) by [rthalley](https://github.com/rthalley). </br>
* [tld](https://github.com/barseghyanartur/tld) by [barseghyanartur](https://github.com/barseghyanartur). </br>

The dependencies will be installed automatically once installing the package.

------------------

### Usage
#### Input Parameters
* domain_name: str -> *mandatory*.
* dkim_selector: str -> *optional*.
* raw_data: bool -> *optional*.

#### Using The Package
CYREBRO's Domain Validator allows you to receive the scan results in both boolean expression and dictionary formats.
###### Importing
```from DomainValidator import validate_domain```
###### Basic Usage
The basic usage will provide you with a simple **True** or **False** answer, it allows for easy check within a condition.</br>
The function will return **True** if the answer is positive for ***one*** of the validity checks mentioned above.  
Example:
```
if validate_domain(domain_name="github.com"):
    do_work()
```
###### Advanced Usage
If a True or False answer does not match your needs, a dictionary is automatically generated upon run. </br>
The dictionary allows one to view the result of each validation separately, for more advanced usage in the code.  
To access the dictionary, simply provide True as the raw_data flag, a dictionary object will be returned.  
Example:

```
domain_validation_details = validate_domain(domain_name="github.com", raw_data=True)
print(domain_validation_details, type(domain_validation_details))
```

**Output:** 

> {  
    "regex": True,  
    "http": True,  
    "https": True,  
    "nslookup": True,   
    "whois": True,    
    "dkim": True,   
    "spf": True   
}
> 
><class 'dict'>

*The dictionary is available even if the domain is not valid.*

### **Note:** the package requires internet connection to work properly.

------------------

##### DKIM Clarification
In order to retrieve the DKIM record of a domain, a specific query is used with a domain-specific [selector](https://www.dmarcanalyzer.com/what-is-a-dkim-selector/). </br>
Due to the nature of this package, we are unable to know in advance the selectors that are used by each domain.</br>
We gathered some common DKIM selectors and the package tries querying with all of them.

However, if you know the DKIM selector in advance (by extracting it from an email for example), the package accepts an arbitrary DKIM selector:</br>
```domain_validator = DomainValidator("github.com", dkim_selector="some_selector")``` </br>
If a specific selector is passed, it will be firstly queried by the package. </br>
If for some reason, a result is unavailable, a fallback was implemented to try all common selectors.

------------------

### Development
Contributing is more than welcome and even encouraged by us. </br>
For any suggestions an email can be sent to: innovation@cyrebro.io. </br>
Pull requests are an option as well :blush: :hugs:.