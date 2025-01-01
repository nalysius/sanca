# Concepts

This document aims to describe the concepts used in Sanca.

The program has three parts which are executed in this order: the readers,
the checkers and the writers.

## Reader

A reader is a structure which reads the data to be analyzed, no matter the source.  
For example, the HttpReader is used to send all the HTTP requests based on the
selected technologies. The HTTP responses are then passed through the checkers.  
Only one reader is used by execution of the program, and is chosen based on the
scan type.

## Checker

A checker is a struct which checks the data given by the reader to say if a
technology is identified.  
For example, the JQueryChecker checks all the HTTP results provided by the reader
and searches for the jQuery library inside.  
If a technology is identified, the checker returnes a list of finding to prove
his point. The findings from all the executed checkers are then sent to the writer.

## Writer

A writer is a struct which outputs the finding in a way that suits the user.  
For example, the JsonWriter prints the findings on STDOUT in the JSON format.  
Only one writer is used by execution of the program, and is chosen by the user.
