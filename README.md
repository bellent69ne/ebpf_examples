# The eBPF samples
In order to successfully compile these samples you have to install BCC(BPF Compiler Collection) version 0.10.0.
If you use Fedora 30 or Ubuntu 18.04 the provided rpm and deb files in bcc_rpm.tar.xz and bcc_deb.tar.xz archives will work as they should:

    $ git clone https://github.com/bellent69ne/ebpf_examples.git
    
    $ cd ebpf_examples
    
    // assume that we use Fedora 30.
    $ tar xf bcc_rpm.tar.xz
    $ cd bcc_rpm
    
    // note that these installations may require some dependencies.
    $ sudo rpm -i libbcc-0.10.0-1.x86_64.rpm
    $ sudo rpm -i python2-bcc-0.10.0-1.x86_64.rpm
    $ sudo rpm -i bcc-0.10.0-1.src.rpm
    // you need to install only these three.
    
In case you don't use Fedora 30 or Ubuntu 18.04 (or it just doesn't get installed) compile BCC from source:

    $ git clone https://github.com/iovisor/bcc.git
    $ cd bcc/scripts
    
    // here you can choose the architecture you want.
    // assume that we want deb packages.
    $ mv build-deb.sh ../
    $ cd ../
    // note that this can fail due to the lack of depedencies.
    // install the required dependencies and try again.
    $ sudo ./build-deb.sh
    
This will build the required packages. 
