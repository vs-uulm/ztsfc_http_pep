# ztsfc_http_pep
ztsfc_pep TLS&amp;HTTP based prototype

# How to run
```ztsfc_http_pep [-help] [-c <path_to_conf_file>] [-log-to <path_to_log_file>|stdout] [-log-level error|warning|info|debug] [-text]```

Following additional components are necessary to run the PEP:
* LDAP server for basic authentication (use for example a [test instance](https://github.com/rroemhild/docker-test-openldap))
* [ztsfc PDP](https://github.com/vs-uulm/ztsfc_http_pdp)
* [ztsfc SFP Logic](https://github.com/vs-uulm/ztsfc_http_sfp_logic)
* [Service Functions](https://github.com/vs-uulm/ztsfc_http_sf_template)
* Target Services

## Configuration file
By default the PEP looks for the ```conf.yml``` in the current directory.

User can redefine the configuration file path with ```-c``` argument.

You can copy [```example_conf.yml```](./example_conf.yml) and adapt it to your needs. It contains further explanations.

## Log output redirect
By default the PEP sends all log messages into the ```pep.log``` file in the current directory.

User can redirect the log output to a file with ```-log-to``` argument.

The parameter ```log-to``` with the value ```stdout``` will print all log messages to the terminal.

## Logging level
By default the PEP has an "Error" logging level. Only Errors and Fatal messages will be shown.

The level "Warning" extends the output in some cases. (Almost never).

To see regular ```http.Server``` and ```httputil.ReverseProxy``` messages please run the PEP with at least "Info" logging level.

The most detailed output can be produced with the "Debug" level.

Logging level value in the command line is case insensitive.


## Logging mode
The PEP logger supports two main logging modes: text and JSON.

JSON mode is turned on by default.

To switch to the text mode just run the PEP with the ```-text``` argument.
