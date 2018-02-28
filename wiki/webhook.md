Webhooks can be setup on a per-organization basis.

The webhook destination URL will receive an HTTP POST in JSON format with the following parameters:
* `secret`: this will be the shared secret string set as the "Webhook Secret".
* `oid`: the organization id related to the investigation or detection.
* `type`: either `detection` or `investigation`.
* `data`: content of the detection or investigation.

Example:
```
POST / HTTP/1.1
Accept-Encoding: identity
Content-Length: 815
Host: 127.0.0.1:6666
Content-Type: application/json
Connection: close
User-Agent: Python-urllib/2.7

{"data": {"tasks": [], "nature": 9, "hunter": "Stage0Hunter", "inv_id": "22A744BD7AF964B5BA5F23F572C49D03235E66B32B8E7D0B9FD64A3FAF58C109", "source": "04a9d860-bcd3-11e6-a56f-8dc8378d2ca2.85489dfd-5752-4fd9-aa91-234614fb8245.0e305a34-0e57-46ff-b695-22ac37b4642e.10000000.2", "generated": "2017-05-26 03:42:44", "closed": "2017-05-26 03:42:48", "data": [{"data": {"explore": "https://limacharlie.io/explore?atid=baefdb91-f6bd-78eb-e534-0728ed78b276"}, "generated": 1495770164317, "hunter": "Stage0Hunter", "why": "investigating file C:\\Users\\dev\\Desktop\\test.jpg.exe"}], "why": "this is a duplicate of https://limacharlie.io/detect?id=84aef502ea8d37a6f5fe570bc39d4254624956016461729c8c4efb4a218cf862", "conclusion": 4}, "secret": "letmein", "oid": "04a9d860-bcd3-11e6-a56f-8dc8378d2ca2", "type": "investigation"}
```