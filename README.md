# betterscan-vanta
Betterscan.io Vanta.com Integration

For use with private GitHub repos.

Run on Computer/server to connect via Oauth2. tokens.json will be generated. Upload tokens.json to desired repo you want to integrate into Vanta under .checkmate folder

Add this to .github/workflows/betterscan-vanta.yml (creating GitHub action)


```
env:
  CLIENT_ID: ${{secrets.CLIENT_ID}}
  CLIENT_SECRET: ${{secrets.CLIENT_SECRET}}
  SOURCE_ID: ${{secrets.SOURCE_ID}}
  RESOURCE_ID: ${{secrets.RESOURCE_ID}}
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
```

It will run every hour pushing resulta to Vanat
           
