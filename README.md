# MPIログ収集モジュール

- BlueField-2 DPU上で実行することを想定
- MPICHの通信チャネルの設定は，`./configure --with-device=ch3:sock ...`対応
- MPICH(mpirun)実行時に、環境変数`MPICH_PORT_RANGE`の設定が必要
- TCP port番号の範囲はこちら (unisonflow-mpichを参考にした)
```c
unsigned short mpich_port_start = 50000;
unsigned short mpich_port_end = 50100;
```

## 実行方法
- DPUのセットアップ [NVIDIA DEVELOPPERS GUIDE](https://docs.nvidia.com/doca/sdk/installation-guide/index.html)
- DPU: dockerのインストール
- DPU: OVS(Open vSwitch)設定
  - https://docs.nvidia.com/doca/sdk/scalable-functions/index.html

- DOCAアプリケーションのビルド
  - [ビルドスクリプト](./build.sh)
  - ARM用のバイナリにコンパイルする必要があるため，ビルド用のdockerコンテナが起動し，コンテナ内でビルドが実行される，ビルドが成功した場合，実行ファイルが`src/build`以下に出力される．

- DOCAアプリケーション実行
- [こちらのサンプルアプリ(simple-forward-vnf)](https://docs.nvidia.com/doca/sdk/simple-forward-vnf/index.html)を参考にしているため，実行方法もこちらに従う．
```bash
# Build DPU application without containers
DPU$ ./src/build_app.sh
# Run the application
DPU$ sudo ./bin/run_mpiid.sh
```


### 評価計測用のサンプルMPIプログラムの実行
- mpichのインストールが必要, mpicc, mpirunが利用できることが必要

## 取得するデータ
- ログ記録時刻(UTC)
- 送信元ノードIP
- 宛先ノードIP
- 送信データサイズ
- MPI関数

## ログファイル出力のバッファリング

- putLogのフロー
	1. バッファされている文字列長buf_lenを取得
	1. if buf_len > LOG_BUF_SIZE
		1. mutex lock
		1. ファイルオープン
		1. ファイルに文字列を出力
		1. ファイルクローズ
		1. mutex free
	1. else
    - bufferに最新のログを追加

## パケット受信，解析処理，送信の実行順序
パケット受信→解析処理→送信の順番で実行すると，解析処理の時間がかかってしまうため，通信遅延時間が大きくなる．

通信遅延時間短縮を目的の一つとしているため，パケット受信→送信までの時間をできるだけ短くする必要がある．

