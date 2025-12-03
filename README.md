# Programming Lightning workshop

The Lightning Network is a protocol built on top of the Bitcoin base layer.
It takes advantage of the programmable nature of Bitcoin transactions to express contracts that allow two parties to make off-chain payments.
Off-chain payments are tricky because, after all, the Bitcoin public blockchain mechanism is one of the cornerstones for preventing double-spending.

This task is a self-paced workshop developed by [Austin Krauss](https://x.com/_austin_f).
It is designed to cover the basic mechanics of how Lightning payments work under the hood.

## Setup

If you don't have a [replit](https://replit.com) account yet, now is a good time to register.
Then, go to the [Programming Lightning Workshop](https://replit.com/@austin-f/Programming-Lightning-Intro-to-Payment-Channels-mini?v=1) project page and click `Remix this app`.
Replit will create a fork of the entire project and you can start working on your own fork of it.

Once the project is opened, you will face a two pane interface (or three, if the AI pop up).
To the left, there will be the tutorial tab that will guide you through explaining how Lightning works and propose some exercises.
On the right pane, you will have a preview pane (which is useless for this workshop).

The panes are based on tabs, you can click the `+` button the open new tabs in each pane.
You'll probably need a `Shell` tab, which is where you issues commands, including the `./start.sh` script which will setup Rust and Bitcoin Core for your environment.

There's a green "play" button on the top-left area.
Use it to run the tests and check your progress.
It takes some time to compile everything in the first run, and off course you should expect to have all tests failing to begin with.
It will open a `Console` tab for you, which is used to display the outputs of the test suite.

Finally, there's an "Open files" button on the top-right side of the screen (it looks like a little square divided in two pieces).
It will open a file explorer pane on the right side of the screen with the files you should edit.

## Submission

There's no Github autograder workflow for this task.
Everything is done in the repl environment, which includes tests for the proposed exercises.

Once you finish the workshop, please get back to this repo and edit the `submissions/done.sh`:

1. include the link to your replit fork so that someone can check your work;
2. change the `"FAIL"` string to 1 `"PASS"` to have the CI notifying us.
