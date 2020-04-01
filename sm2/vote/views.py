from django.shortcuts import render
from django.http.response import JsonResponse

from vote.models import *
from vote import sm2

# Create your views here.

sm = sm2.SM2()
sk, pk = sm.generate_keys()
print('公钥x值：', str(sm._elem2int(pk.x)))
print('公钥y值：', str(sm._elem2int(pk.y)))


def register(request):
    if request.method == 'POST':
        u = request.POST.get("username")
        s = request.POST.get("password")
        # print(u, s)
        if not Users.objects.filter(username=u):
            Users.objects.create(username=u, password=s)
            return JsonResponse({"params": {"result": "ok"}})

        return JsonResponse({"params": {"result": "exists"}})
    return render(request, "register.html")


def login(request):
    if request.method == 'POST':
        u = request.POST.get("username")
        s = request.POST.get("password")

        ques = Users.objects.get(username=u)
        if ques.password == s:
            return JsonResponse(
                {"params": {"result": "ok", "pkx": str(sm._elem2int(pk.x)), "pky": str(sm._elem2int(pk.y)),
                            "uid": str(ques.id)}})
        return JsonResponse(
            {"params": {"result": "notfound"}})
    return render(request, "register.html")


def votes(request):
    data = []
    book = Tickets.objects.values()
    for ticket in book:
        # print(ticket)
        data.append(ticket)
    print (data)
    return JsonResponse({"params": {"cards": data}})


def choose(request):
    data = request.POST.get("m")
    data = data.split("|")
    r1, a, b, d = int(data[0]), int(data[1]), int(data[2]), int(data[3])
    s = sm.sign(r1, sk, a, b, d)
    # print(s)
    try:
        return JsonResponse({"params": {"result": "ok", "sign": str(s)}})
    except Exception:
        return JsonResponse({"params": {"result": "exists"}})



def verify(request):
    m = request.POST.get("m")
    M = m.encode("utf-8")
    uid = str.encode(request.POST.get("u"),"utf-8")
    r = request.POST.get("r")
    s = request.POST.get("s")

    ques= Users.objects.get(id=request.POST.get("u"))
    try:
        tickets=ques.ut.split("|")
        if tickets.count(m.split("|")[0])==0:
            pass
        else:
            return JsonResponse({"params": {"result": "exists"}})
    except Exception:
        pass


    # print(m,request.POST.get("u"),pk,r,s)
    if sm.verify(M, uid, pk, int(r),int(s)):
        Votes.objects.create(votemes=s)
        if m.split("|")[1] == 'up':
            tickets = Tickets.objects.get(id=m.split("|")[0])
            tickets = int(tickets.up)
            Tickets.objects.filter(id=m.split("|")[0]).update(up=str(tickets + 1))

            utb=Users.objects.get(id=uid)
            Users.objects.filter(id=uid).update(ut=str(utb.ut)+"|"+m.split("|")[0])
            return JsonResponse({"params": {"result": "ok"}})
        else:
            tickets = Tickets.objects.get(id=m.split("|")[0])
            tickets = int(tickets.down)
            Tickets.objects.filter(id=m.split("|")[0]).update(down=str(tickets + 1))

            utb=Users.objects.get(id=uid)
            Users.objects.filter(id=uid).update(ut=str(utb.ut)+"|"+m.split("|")[0])
            return JsonResponse({"params": {"result": "ok"}})
    else:
        return JsonResponse({"params": {"result": "error"}})
