# Next Steps

The idea is to brainstorm improvements, bugs to fix, and new features, so we can meet and discuss them, and build a priority matrix to see in which ones we should focus first:

- Low effort – Low impact  
- High effort – Low impact  
- High effort – High impact  
- Low effort – High impact  

―Understanding of common smart contract vulnerabilities (e.g., reentrancy, access control) and
LLM integration [DONE]

―Develop a programmatic pipeline integrating an LLM API to analyze raw contract source code [DONE]

―Benchmark the custom tool against a known dataset of vulnerable contracts (e.g., SmartBugs)
to evaluate precision and recall[DONE]

―Build a tool (CLI or UI) that accepts a contract and outputs a structured vulnerability report [DONE]

―Submit a report detailing the system architecture, prompt/context strategies, and a critical
analysis of the LLM's performance versus traditional static analyzers


## Brainstorming -> things to improve, new features, bug resolution, things to do, etc (whatever you have in mind)

1. Overcome the token limitation of Grok.  
   Currently, smart contracts + prompts cannot be very long, and we may only be able to analyze around 15 per day before reaching the token limit.
2. Collect a dataset of Smart Contracts with labeled vulnerabilities (through SmartBugs dataset)
3. Implement evaluation pipeline.
4. Add INFO category as a card in Frontend
5. Enhance Slither formating in frontend
6. Next Monday we should enter the QA and ask the instructors how we should go about it, because if I remember correctly we will also have to use the UZH PoS Blockchain in some manner. Although, at the moment I cannot comprehend how.
7. We also have to do the report and the presentation.
8. I have ran the tests, you can see the results in the evaluation folder. They are interesting. I used the other model with less tokens to run it once, otherwise it would take multiple days. Check llm-node.py comments.
