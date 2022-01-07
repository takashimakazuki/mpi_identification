# MPIログ収集モジュール

- DPU上で実行することを想定
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
- [こちらのサンプルアプリ(simple-forward-vnf)](https://docs.nvidia.com/doca/sdk/simple-forward/index.html)を参考にしているため，実行方法もこちらに従う．
```bash
sudo ./log_mpi -a auxiliary:mlx5_core.sf.4 -a auxiliary:mlx5_core.sf.5 -- --nr_queues=2 --log_level=8 
```

## 取得するデータ
- ログ記録時刻(UTC)
- 送信元ノードIP
- 宛先ノードIP
- 送信データサイズ
- MPI関数

## ログファイル出力のバッファリング

- setvbufを用いてバッファリングを実装
