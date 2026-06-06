\# top-level: paper title, abstract, link to paper, quick-start



The README.md must contain a one‑command reproduction path, for example:



\# 1. Build all Docker images

cd docker \&\& for t in cln lnd ldk eclair; do

&#x20; docker build -f ${t}.Dockerfile --build-arg COMMIT\_HASH=... -t smite-${t} .

done



\# 2. Run the baseline campaign for a single bug

cd orchestrator \&\& python run\_trial.py --bug CVE-2023-0001 --scenario raw-bytes --trials 5 --timeout 24h



\# 3. Analyze results

cd analysis \&\& Rscript survival\_analysis.R ../results/







Before the paper’s camera‑ready deadline, upload a snapshot of the entire repository (including Git history) to Zenodo or Figshare to get a permanent DOI.



Reference that DOI in the paper’s “Artifact Availability” section.

