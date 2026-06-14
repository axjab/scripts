# Scripts

## Recently added

### Best template

Template to follow when creating new scripts

### Scripts and purpose
| script | description                            |      usage     | dependencies | modified   | description |
|:------:|----------------------------------------|:--------------:|:------------:|------------|-------------|
|  see  | Opens stdin content in the default app | `cat pdf \| see` | xdg-open     | 2024-11-17 | 2024-11-17  |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |
|        |                                        |                |              |            |             |

## ?

All files here are executable save for this one.
This means from anywhere in bash, entering the name of the file executes the file itself.
Here's how to do this:

1. `touch ~/bin/<script>` (without extension)
2. `code ~/bin/<script>`
3. On first line, add shebang
	#!/bin/bash            – Execute the file using the Bash shell
	#!/usr/bin/pwsh	       – Execute the file using PowerShell
	#!/usr/bin/env python3 – Execute with a Python interpreter
	#!/bin/false 	       – Do nothing, but return a non-zero exit status, indicating failure. Used to prevent stand-alone execution of a script file intended for execution in a specific context
4. Run `activate <script>` to make it executable (chmod +x ~/bin/<script>).

Done. The script is now ready to be executed.

**Note for all repos**: to push to new repo must do this:

1. Use generated token
2. for user or password enter token

See https://stackoverflow.com/questions/18935539/authenticate-with-github-using-a-token
