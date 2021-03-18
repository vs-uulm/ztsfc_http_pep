# ztsfc_http_pep
ztsfc_pep TLS&amp;HTTP based prototype

# How to run
ztsfc_http_pep [-conf <path_to_conf_file>] [-log-to <path_to_log_file>|stdout] [-log-level error|warning|info|debug] [-text]

## Configuration file
By default the PEP looks for the "conf.yml" in the current directory.

User can redefine the configuration file path with "-conf" argument.

## Log output redirect
By default the PEP sends all log messages into the "pep.log" file in the current directory.

User can redirect the log output to a file with "-log-to" argument.

The parameter "log-to" with the value "stdout" will print all logwriter messages to the terminal.

## Logging level
By default the PEP has an "Error" logging level. Only Errors and Fatal messages will be shown.

The level "Warning" extends the output in some cases. (Almost never).

To see regular http.Server and httputil.ReverseProxy messages please run the PEP with at least "info" logging level.

The most detailed output can be produced with the "debug" level.

Logging level value in the command line is case insensitive.


## Logging mode
The PEP logwriter supports two main logging modes: text and JSON.

JSON mode is turned on by default.

To switch to the text mode just run the PEP with the "-text" argument.
