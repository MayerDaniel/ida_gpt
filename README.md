# ida_gpt
ChatGPT loves IDA!

## Dependencies
This idapython script requires the unofficial chatgpt api implementation found [here](https://github.com/taranjeet/chatgpt-api).

If you change the server port to something other than 5001, be sure you change it in the idapython script as well!

I also found that dumping a bunch of disassembly into GPT sometimes makes it take a long time. I changed my sleep time in `server.py` to be 15 seconds just to be safe.

## Usage
This is a basic idapython script to get you started with analyzing disassembly with GPT

The script has two functions designed for being called on the address of a subroutine:

*1. get_description(ea)*

This function will provide GPT with the disassembly of the subroutine and request a plain-text description. It is then added to IDA as a function comment.


*2. refactor*

This is best called after `get_description` so GPT has a better understanding of the function. It will request variable and location name suggestions from GPT, as well as a function name. These are then written to your idb.

## See it in action!

Here's a video of it renaming some variables, locations, and the function name of an rc4 algorithm in a piece of malware. 

You can also see the description comment it created for the function at the top of the IDA window

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Boom! Got variable and function renaming going as well. I found that the full function descriptions can get a little tough, but even if the description is a little off, it will suggest accurate names for the variables. <a href="https://t.co/QkBcgT4Nxw">pic.twitter.com/QkBcgT4Nxw</a></p>&mdash; Daniel Mayer (@dan__mayer) <a href="https://twitter.com/dan__mayer/status/1599349464195481600?ref_src=twsrc%5Etfw">December 4, 2022</a></blockquote>
