# betterscan-vanta
Betterscan.io Vanta.com Integration

In order to integrate it, get a Vanta subscription. 

In you Vanta installation go to `Settings->Developer Console`



Click `Create+`

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/8c8713c8-df8b-4864-be31-d9478b639bac)

*Fig. 1*

Fill out this info:

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/d5f78bb5-b5ed-4de8-a5a9-be28409c5af1)

*Fig. 2*

Click `Generate Oauth secret`

Clck `Save`

Run on your Computer/serve

`python client.py`

It will connect via Oauth2 to Vanta. `tokens.json` will be generated. Upload `tokens.json` to desired repo you want to integrate into Vanta under .checkmate folder

Create approperiate resources

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/b549f5df-f71b-4599-b9e8-39a6f598e1cd)

*Fig. 3*

`VulnerableComponent` and `StaticAnalysisCodeVulnerabilityConnectors`

Set those as Environmenta variables:

```
CLIENT_ID:
CLIENT_SECRET: 
SOURCE_ID: 
RESOURCE_ID_VULNCOMP:
RESOURCE_ID_SAST: 
LIC: 
```

You can use a job in any CI/CD to run in at intervals.

Below is sample for use with private GitHub repos. GitHub actions are free also for private repos.

Add this to `.github/workflows/betterscan-vanta.yml` (creating GitHub action)


```
env:
  CLIENT_ID: ${{secrets.CLIENT_ID}}
  CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
  SOURCE_ID: ${{secrets.SOURCE_ID}}
  RESOURCE_ID_VULNCOMP: ${{secrets.RESOURCE_ID_VULNCOMP}}
  RESOURCE_ID_SAST: ${{secrets.RESOURCE_ID_SAST}}
  LIC: ${{secrets.LIC}}
  

name: Betterscan Scan Vanta

on:
  # Triggers the workflow every hour
  schedule:
    - cron: "0 * * * *"
jobs:
  Betterscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - name: Betterscan Scan
        uses: topcodersonline/betterscan@v3
      - name: Move tokens
        run : |
           mv .checkmate/tokens.json tokens.json
      - name: Betterscan Vanta Action
        uses: topcodersonline/betterscan-vanta@v1
      - name: Check if there are any changes
        id: verify_diff
        run: |
          tree
          rm -rf code
          mv tokens.json .checkmate/tokens.json
          git diff --quiet . || echo "changed=true" >> $GITHUB_OUTPUT
      - name: Commit
        if: steps.verify_diff.outputs.changed == 'true'
        run: |
           sudo chown -R "${USER:-$(id -un)}" .
           git config --global user.email "bot@betterscan.io"
           git config --global user.name "Betterscan.io Bot"
           git add .checkmate/tokens.json && git commit -m "tokens"
           git push origin `git rev-parse --abbrev-ref HEAD`

  
```

It will run every hour pushing resulta to Vanta

Will look like this

Date: 21/06/2023

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/a1b25054-330e-4637-959d-c8c232bfb837)

*Fig. 4*

Here is connected integration:

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/a1f24f9c-ff5a-4191-8368-3f2417000b89)

*Fig. 5*

via these settings:

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/230127dc-5831-498a-a9ad-e708e15764cc)

*Fig. 6*

and required and approperiate resources:

![image](https://github.com/marcinguy/betterscan-vanta/assets/20355405/b6f17219-c519-4915-a70a-861812535903)

*Fig. 7*
