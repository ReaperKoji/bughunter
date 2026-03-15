# Application BAC Probe - 20260308_214823

- service_base: `https://webwsp.aps.kuleuven.be/sap/opu/odata/sap/ZC_AD_APPLICANT_SRV`
- app_a: `000000479956`
- app_b: `000000479928`
- cookie_a_len: `2967`
- cookie_b_len: `2573`

## Requests
- actor=A relation=own_application endpoint=CommunicationSet target_app=000000479956 status=200 json=True login_like=False nonempty=True app_ids=['000000479956']
- actor=A relation=own_application endpoint=ApplicationsByIdFilter target_app=000000479956 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=A relation=own_application endpoint=ApplicationsEntityKey target_app=000000479956 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=A relation=own_application endpoint=SubmitChecksNav target_app=000000479956 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=A relation=own_application endpoint=AttachmentsNav target_app=000000479956 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=A relation=cross_application endpoint=CommunicationSet target_app=000000479928 status=200 json=True login_like=False nonempty=True app_ids=['000000479928']
- actor=A relation=cross_application endpoint=ApplicationsByIdFilter target_app=000000479928 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=A relation=cross_application endpoint=ApplicationsEntityKey target_app=000000479928 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=A relation=cross_application endpoint=SubmitChecksNav target_app=000000479928 status=403 json=True login_like=False nonempty=False app_ids=[]
- actor=A relation=cross_application endpoint=AttachmentsNav target_app=000000479928 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=B relation=cross_application endpoint=CommunicationSet target_app=000000479956 status=200 json=True login_like=False nonempty=True app_ids=['000000479956']
- actor=B relation=cross_application endpoint=ApplicationsByIdFilter target_app=000000479956 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=B relation=cross_application endpoint=ApplicationsEntityKey target_app=000000479956 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=B relation=cross_application endpoint=SubmitChecksNav target_app=000000479956 status=403 json=True login_like=False nonempty=False app_ids=[]
- actor=B relation=cross_application endpoint=AttachmentsNav target_app=000000479956 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=B relation=own_application endpoint=CommunicationSet target_app=000000479928 status=200 json=True login_like=False nonempty=True app_ids=['000000479928']
- actor=B relation=own_application endpoint=ApplicationsByIdFilter target_app=000000479928 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=B relation=own_application endpoint=ApplicationsEntityKey target_app=000000479928 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=B relation=own_application endpoint=SubmitChecksNav target_app=000000479928 status=200 json=True login_like=False nonempty=True app_ids=[]
- actor=B relation=own_application endpoint=AttachmentsNav target_app=000000479928 status=200 json=True login_like=False nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=CommunicationSet target_app=000000479956 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=ApplicationsByIdFilter target_app=000000479956 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=ApplicationsEntityKey target_app=000000479956 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=SubmitChecksNav target_app=000000479956 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=AttachmentsNav target_app=000000479956 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=CommunicationSet target_app=000000479928 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=ApplicationsByIdFilter target_app=000000479928 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=ApplicationsEntityKey target_app=000000479928 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=SubmitChecksNav target_app=000000479928 status=200 json=False login_like=True nonempty=False app_ids=[]
- actor=ANON relation=unauthenticated endpoint=AttachmentsNav target_app=000000479928 status=200 json=False login_like=True nonempty=False app_ids=[]

## Verdict
- potential_cross_read_on_communication: `True`
- potential_cross_read_on_applications_filter: `False`
- potential_cross_read_on_nav_collections: `False`
- notes: `Cross-account read accepted on CommunicationSet by applicationId.`
