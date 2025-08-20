# PMYS Ajan

## Kurulum
Sanal ortamı kurun:
```bash
python3 -m venv venv
source venv/bin/activate
```
Burası opsiyonel, pip ve wheel sürümlerini yükseltmek gerekirse:
```bash
pip install --upgrade pip
pip install --upgrade wheel
```
Paketleri kurun:
```bash
pip install -r requirements.txt
```

## Konfigürasyon
Öncelikle agent.conf.template dosyası kopyalayıp adını agent.conf yapın.
```bash
cp agent.conf.template agent.conf
```
İçerisindeki ilgili kısımları doldurun.

## Başlatmak İçin
Uygulamayı başlatın
```bash
python main.py
```