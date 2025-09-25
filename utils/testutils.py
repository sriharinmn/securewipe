def create_test_drive(size_mb: int = 100) -> str:
    """
    Create a test drive using a loop device
    
    Args:
        size_mb: Size of the test drive in megabytes
        
    Returns:
        Path to the created loop device
    """
    import subprocess
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    test_file = '/tmp/test_drive_loop.img'
    
    try:
        # Create the test file
        subprocess.run(['dd', 'if=/dev/zero', f'of={test_file}', 'bs=1M', f'count={size_mb}'],
                      check=True, capture_output=True)
                      
        # Set up loop device
        result = subprocess.run(['losetup', '--find', '--show', test_file],
                              check=True, capture_output=True, text=True)
        loop_device = result.stdout.strip()
        
        # Set permissions
        subprocess.run(['chown', f'{os.environ.get("USER")}:{os.environ.get("USER")}', loop_device],
                      check=True, capture_output=True)
        subprocess.run(['chmod', '660', loop_device],
                      check=True, capture_output=True)
                      
        logger.info(f"Created test drive at {loop_device}")
        return loop_device
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create test drive: {e}")
        if os.path.exists(test_file):
            try:
                os.remove(test_file)
            except:
                pass
        raise