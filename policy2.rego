package accurics

# Use this one in that open Rego policy checker.

# This is an example for a Rego rule. The value inside the brackets [array.id] is returned if the rule evaluates to be true.
# Portions of the code below in the comments were created by Eric J. Kao on Styra Academy
#  regex.match("company_name.*", bucket_name)

default allow = false

allow  { #do I need input.aws_s3_bucket outside the brackets?
  array := input.aws_s3_bucket[_]
	array.config.bucket == "Cloudavail*"
 
  }
